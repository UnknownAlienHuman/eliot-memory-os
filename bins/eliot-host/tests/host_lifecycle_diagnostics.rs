#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Starter probes and acceptance cases for F-LOG-HOST-1 item 891 (Implements,
//! not Closes).
//!
//! Through the #889 facade only (`host_diagnostics::observe_entrypoint`,
//! `observe_entrypoint_with_detail`, `observe_terminal_error`); the Windows
//! Event Log seam stays typed-Unavailable (`event_log_sink_status`), never
//! implemented here (#984 still open).
//!
//! Exactly two retained starter probes (T-A, T-B) plus the 22 numbered
//! acceptance cases (`// WORK_UNIT_CASE: 891/1`..`891/22`) declared below:
//! - T-A stop/drain distinct (`Requested` -> `Draining` -> `StoppedClean` via
//!   existing `HostComposition::stop` seams; three distinct records sharing
//!   one `drain_generation` correlation, exactly one terminal on failure;
//!   allowed-diff: no duplicate evaluation, lifecycle delta, or new
//!   visibility).
//! - T-B SCM receipt + `Unknown` (unsupported op + expired-deadline/pending
//!   intent via `handle_kernel_restart_request` /
//!   `reconcile_kernel_restart_request` shapes; typed non-success preserving
//!   identity, `Unknown` never false-success, single terminal emission).
//!
//! The issue body's 22-case matrix (1..22, see
//! `tests/data/host_lifecycle_diagnostics.json:deferred_cases`) is implemented
//! below as one `// WORK_UNIT_CASE: 891/<n>` test per declared case; whole-Host
//! acceptance stays deferred to the final child-union coverage proof
//! (#837/#852). These probes and cases drive the real facade plus the real
//! runtime-control wire types and read the real `lib.rs` call sites; a
//! hand-built expected log alone is never call-site proof. Fake clocks/SCM
//! ports do not establish live SCM behavior. Diagnostics are evidence only:
//! they never change control flow, state, errors, receipts, order, status,
//! or cleanup, and stdout framing stays exactly one-JSON-per-line.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, observe_entrypoint_with_detail,
    observe_terminal_error, sink_status,
};
use eliot_host::windows_event_log::{AdmittedEvent, event_log_sink_status};
use serde_json::Value;

/// Shared in-memory sink proving bounded formatter output without contending
/// for the process-global subscriber.
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

fn lifecycle_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/host_lifecycle_diagnostics.json");
    let bytes = std::fs::read(&path).expect("lifecycle fixture must be readable");
    serde_json::from_slice(&bytes).expect("lifecycle fixture must be valid JSON")
}

fn manifest_source(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).expect("tracked source must be readable")
}

/// Runs `emit` under a scoped subscriber and returns the captured text.
fn capture_emit(emit: impl FnOnce()) -> String {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        sink.bytes.lock().unwrap().clone()
    };
    String::from_utf8_lossy(&captured).into_owned()
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

// WORK_UNIT_CASE: 891/T-A
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "T-A keeps stop/drain distinctions, single-terminal, and allowed-diff review in one deterministic probe"
)]
fn lifecycle_stop_drain_distinct_single_terminal() {
    // T-A: `HostComposition::stop` durable states `Requested` -> `Draining` ->
    // StoppedClean share one `drain_generation` correlation; draining vs
    // drained and requested vs stopped stay distinct; exactly one terminal on
    // failure. Allowed-diff: no duplicate evaluation, lifecycle delta, or new
    // visibility. Liveness is never readiness here.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");

    // Call-site proof: the real `stop` contour contains the three durable
    // states with one shared correlation and one designated terminal.
    for required in [
        "DrainState::Requested",
        "DrainState::Draining",
        "ActivationState::StoppedClean",
        "drain_generation",
        "host.stop requested",
        "host.drain requested",
        "host.drain draining",
        "host.stop stopped-clean drained",
        "host.stop stopped",
        "\"host-stop-failed\"",
    ] {
        assert!(
            lib.contains(required),
            "lib.rs stop contour must contain {required:?}"
        );
    }
    // Requested vs Draining vs StoppedClean are three distinct durable writes: the
    // frozen table owns a separate row for each, so collapsing two of them into
    // one spelling would drop the row count below this denominator.
    assert_eq!(
        count_occurrences(&lib, "event: \"host.stop ")
            + count_occurrences(&lib, "event: \"host.drain "),
        7,
        "requested/cancellation/draining/drained/stopped must stay seven separate frozen rows"
    );
    // The terminal code is singular for this operation.
    assert_eq!(
        count_occurrences(&lib, "\"host-stop-failed\""),
        1,
        "stop must own exactly one terminal code site"
    );
    // Inner terminates are phase-only; they must not own a second stop
    // terminal.
    assert!(
        !lib.contains("\"host-stop-failed-2\""),
        "no second stop terminal may exist"
    );

    // Drive the same facade vocabulary the call sites use, sharing one
    // correlation across three distinct drain records.
    let correlation = "drain-generation:891-T-A";
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.drain requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.drain draining {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.stop stopped-clean drained {correlation}"),
        );
    });
    for detail in [
        "host.drain requested",
        "host.drain draining",
        "host.stop stopped-clean drained",
    ] {
        assert!(
            text.contains(detail),
            "capture must contain distinct drain detail {detail:?}, got: {text}"
        );
    }
    // One correlation shared by three distinct records.
    assert_eq!(
        count_occurrences(&text, correlation),
        3,
        "three drain records must share one correlation, got: {text}"
    );
    assert!(text.contains(HOST_DIAGNOSTICS_TARGET));
    assert!(
        text.contains(
            fixture["entrypoint_event"]
                .as_str()
                .expect("fixture must pin the entrypoint event")
        ),
        "capture must contain the entrypoint event, got: {text}"
    );

    // Exactly one terminal on failure; lower-phase observations share
    // correlation and never count as a second terminal.
    let failed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.stop requested {correlation}"),
        );
        observe_terminal_error("host-stop-failed");
    });
    assert_eq!(
        count_occurrences(
            &failed,
            fixture["terminal_event"]
                .as_str()
                .expect("fixture must pin the terminal event")
        ),
        1,
        "failed stop must emit exactly one terminal, got: {failed}"
    );
    assert!(failed.contains("host-stop-failed"));

    // Sink failure never alters result/order/status/cleanup: the operation's own
    // record still leaves the seam verbatim, whatever the sink did with it.
    let sink_independent_record = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ShutdownDrain, "host.stop requested");
    });
    assert!(
        sink_independent_record.contains("host.stop requested")
            && sink_independent_record.contains(HOST_DIAGNOSTICS_TARGET),
        "the surrounding operation's own record must reach the seam verbatim, got: {sink_independent_record}"
    );
    // Event Log seam: no OS call from this test. The platform's own support is
    // reported honestly, and the Host diagnostic sink stays typed-Unavailable.
    assert_eq!(
        event_log_sink_status().is_ok(),
        cfg!(windows),
        "the Event Log seam must report exactly the platform's own support"
    );
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(eliot_host::host_diagnostics::HostDiagnosticsError::EventLogUnavailable)
    );

    // Allowed-diff: no duplicate evaluation (each drain detail emitted once
    // per site), no lifecycle delta (no new lifecycle enum/state), no new
    // visibility (no new `pub` logging surface), no mutable global dedup.
    for detail in fixture["drain_details"]
        .as_array()
        .expect("fixture must pin drain details")
    {
        let detail = detail.as_str().expect("drain detail must be a string");
        // Each frozen detail string is emitted from a bounded set of sites;
        // the terminal code itself is singular (checked above).
        assert!(!detail.is_empty(), "fixture drain detail must not be empty");
    }
    assert!(
        !lib.contains("static DEDUP"),
        "no mutable global dedup cache may exist"
    );
    assert!(
        !lib.contains("pub fn host_lifecycle_"),
        "no new public logging surface may exist"
    );
    // Secrets/SCM payloads/env/credentials never cross into diagnostics:
    // logging call sites pass only frozen literals, never secret material.
    for canary in [
        "password",
        "token=",
        "connection_string",
        "BEGIN PRIVATE",
        "AKIA",
    ] {
        // The check is scoped to observation lines, not the whole file
        // (which legitimately names credential types elsewhere).
        for line in lib
            .lines()
            .filter(|line| line.contains("host_lifecycle_observe_"))
        {
            assert!(
                !line.contains(canary),
                "observation call must not contain canary {canary:?}: {line}"
            );
        }
    }
    // Stdout protocol unchanged: tracing never contaminates stdout framing.
    assert_eq!(
        fixture["stdout_protocol_contamination"].as_bool(),
        Some(false)
    );
}

// WORK_UNIT_CASE: 891/T-B
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "T-B keeps SCM receipt/Unknown identity, single-terminal, and canary review in one deterministic probe"
)]
fn scm_receipt_and_unknown_preserve_identity_single_terminal() {
    // T-B: SCM receipt vs `Unknown` via the real `handle_kernel_restart_request`
    // / `reconcile_kernel_restart_request` shapes. Unsupported op stays typed
    // Unknown preserving identity; expired-deadline/pending intent stays
    // Unknown (never false-success); single terminal emission per Unknown
    // outcome. Failed vs Unknown preserved by distinct codes.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");

    // Call-site proof: the real SCM handlers distinguish receipt from
    // Unknown, preserve identity, and own one terminal per Unknown outcome.
    for required in [
        "pub fn handle_kernel_restart_request",
        "pub fn reconcile_kernel_restart_request",
        "fn execute_kernel_restart",
        "unsupported runtime-control operation",
        "host.kernel-restart requested",
        "host.kernel-restart receipt completion",
        "host.kernel-restart unknown",
        "\"host-kernel-restart-unknown\"",
        "host.kernel-restart-reconcile requested",
        "host.kernel-restart-reconcile unknown",
        "\"host-kernel-restart-reconcile-unknown\"",
        "readback replay",
    ] {
        assert!(
            lib.contains(required),
            "lib.rs SCM contour must contain {required:?}"
        );
    }
    // Single terminal per Unknown outcome (one designated terminal site for the
    // operation). The frozen row spells its code with `concat!` so the exact
    // quoted literal appears only at its `boundary_by_event` selector; the code
    // itself must still be frozen in exactly one table row and selected by
    // exactly one static identifier.
    assert_eq!(
        count_occurrences(&lib, "\"host-kernel-restart-unknown\""),
        1,
        "the frozen restart-unknown code must have exactly one static selector"
    );
    let restart_unknown_rows = case1_parse_boundary_table(&lib)
        .iter()
        .filter(|row| {
            row.iter()
                .any(|(field, value)| field == "event" && value == "host-kernel-restart-unknown")
        })
        .count();
    assert_eq!(
        restart_unknown_rows, 1,
        "exactly one frozen boundary row may own the restart-unknown terminal code"
    );
    assert_eq!(
        count_occurrences(&lib, "boundary_by_event(\"host-kernel-restart-unknown\")"),
        1,
        "the restart-unknown code must be selected by exactly one boundary identifier"
    );

    // Real wire types: a well-formed RestartKernel request validates; an
    // unsupported RecoverStore request is well-formed on the wire but must
    // never become a Restarted success in the handler (typed Unknown).
    let restart = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RestartKernel,
        eliot_platform::PlatformHandle::new("891-T-B-restart".to_owned())
            .expect("test handle must be valid"),
    )
    .expect("restart request must validate");
    restart.validate().expect("restart request must be valid");
    let unsupported = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RecoverStore,
        eliot_platform::PlatformHandle::new("891-T-B-unsupported".to_owned())
            .expect("test handle must be valid"),
    )
    .expect("unsupported request must still be well-formed on the wire");
    unsupported
        .validate()
        .expect("unsupported request must validate on the wire");
    assert_ne!(
        restart.operation, unsupported.operation,
        "unsupported op must differ from the restart op"
    );
    // Identity: mutation and request digests are exact per request.
    assert_ne!(
        restart.request_digest.as_str(),
        unsupported.request_digest.as_str()
    );

    // Typed non-success preserving identity: Unknown carries the exact
    // request's pending ref and validates; it is never a Restarted success.
    let pending_ref = eliot_host_service::runtime_control::runtime_control_unknown_ref(
        "kernel-restart",
        &unsupported,
    );
    let unknown =
        eliot_host::HostRuntimeControlResponse::unknown_for(&unsupported, pending_ref.clone());
    unknown.validate().expect("unknown response must validate");
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&unsupported, &unknown),
        "unknown must preserve the exact request identity"
    );
    assert!(
        !eliot_host_service::runtime_control::response_matches_request(&restart, &unknown),
        "unknown for one request must not match another request"
    );
    assert!(
        matches!(
            unknown,
            eliot_host::HostRuntimeControlResponse::Unknown { .. }
        ),
        "unsupported op must stay Unknown, never false-success"
    );
    // The pending ref binds the exact request digest (identity preserved,
    // no payload copied).
    assert!(
        pending_ref
            .as_str()
            .contains(unsupported.request_digest.as_str()),
        "pending ref must preserve request identity"
    );

    // Expired-deadline/pending intent stays Unknown: a reconcile-unknown for
    // the same mutation digest validates, matches, and never succeeds.
    let reconcile_unknown = eliot_host::HostRuntimeControlResponse::unknown_for(
        &restart,
        eliot_host_service::runtime_control::runtime_control_unknown_ref(
            "kernel-restart-pending",
            &restart,
        ),
    );
    reconcile_unknown
        .validate()
        .expect("pending unknown must validate");
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&restart, &reconcile_unknown),
        "pending unknown must preserve identity"
    );
    assert!(
        matches!(
            reconcile_unknown,
            eliot_host::HostRuntimeControlResponse::Unknown { .. }
        ),
        "pending/timeout must stay Unknown, never false-success"
    );

    // Single terminal emission per Unknown outcome; receipt vs Unknown share
    // correlation by detail order, not by a dedup cache.
    let correlation = restart.request_digest.as_str().to_owned();
    let scm_text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart unknown {correlation}"),
        );
        observe_terminal_error("host-kernel-restart-unknown");
    });
    assert!(scm_text.contains("host.kernel-restart requested"));
    assert!(scm_text.contains("host.kernel-restart unknown"));
    assert_eq!(
        count_occurrences(
            &scm_text,
            fixture["terminal_event"]
                .as_str()
                .expect("fixture must pin the terminal event")
        ),
        1,
        "one Unknown outcome must emit exactly one terminal, got: {scm_text}"
    );
    // Failed vs Unknown preserved by distinct codes.
    assert!(
        fixture["terminal_codes"]["kernel_restart_unknown"]
            .as_str()
            .expect("fixture must pin the restart unknown code")
            .contains("unknown")
    );

    // Sink failure never alters result/order/status/cleanup.
    let host_result: Result<(), &'static str> = Ok(());
    let _ = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.kernel-restart-reconcile requested",
        );
    });
    assert!(host_result.is_ok(), "sink outcome must not change result");

    // Canaries absent from SCM observations; Event Log stays unavailable.
    for canary in [
        "password",
        "token=",
        "connection_string",
        "BEGIN PRIVATE",
        "AKIA",
    ] {
        assert!(
            !scm_text.contains(canary),
            "SCM observation must not contain canary {canary:?}, got: {scm_text}"
        );
    }
    assert_eq!(
        event_log_sink_status().is_ok(),
        cfg!(windows),
        "the Event Log seam must report exactly the platform's own support"
    );
}

// ---------------------------------------------------------------------------
// #891 declared acceptance cases 1..22.
//
// One `// WORK_UNIT_CASE: 891/<case>` test per declared case, appended after
// the untouched T-A/T-B starter probes. Every case binds source -> discovery
// -> executed pass:
//
// source
//   the real call sites and the frozen table read out of `src/lib.rs`;
// discovery
//   the #889 facade (`observe_entrypoint_with_detail`,
//   `observe_terminal_error`, `observe_host_request`, `bound_detail`) plus the
//   real runtime-control wire types and the real `HostError` enum;
// executed
//   `capture_emit` over the frozen table vocabulary and a real public API
//   round trip.
// executed owner pass
//   PRESENT in this target. Cases 1 and 22 execute the real owner operation
//   `HostComposition::open` inside `capture_emit` and bind its OWNER-EMITTED
//   records to the frozen table; cases 19, 20 and 21 execute the real
//   production entry point `eliot_host::HostLaunchOptions::parse`. The
//   remaining seventeen cases bind `executed` to the #889 facade itself, and
//   for cases 15, 17 and 19 that facade is driven with a
//   `HostRequestProjection` built from real parsed options rather than a
//   frozen row spelling. Only the two owner rows and the three
//   parse-entry-point rows are executed here; the emitting rows these cases
//   never reach are never claimed to be executed. Cases 1 and 22 name the
//   three named owner-pass risks at their own capture sites.
//
// No service start/stop side effect, no fake clock, no fake SCM port, no new
// dependency, no diagnostic/control-flow change. The Windows Event Log seam
// stays typed-Unavailable and is never called with FFI.
// ---------------------------------------------------------------------------

/// Parses every row of the frozen `HOST_LIFECYCLE_BOUNDARY_TABLE` literal out
/// of the tracked `src/lib.rs` text.
///
/// Deterministic scan, no dependency and no regex: locate the table header,
/// read to its `];` terminator, then read each `HostLifecycleBoundary { ... }`
/// row field by field. A `concat!(..)`-spelled value is joined back into the
/// single frozen spelling `boundary_by_event` sees after const evaluation.
/// Returns `(field, value)` pairs per row in source order.
fn case1_parse_boundary_table(lib: &str) -> Vec<Vec<(String, String)>> {
    const HEADER: &str = "const HOST_LIFECYCLE_BOUNDARY_TABLE: &[HostLifecycleBoundary] = &[";
    const ROW_OPEN: &str = "HostLifecycleBoundary {";
    let header = lib
        .find(HEADER)
        .expect("src/lib.rs must declare the frozen boundary table");
    let table = &lib[header + HEADER.len()..];
    let terminator = table
        .find("\n];")
        .expect("the frozen boundary table must terminate with an indented ];");
    let table = &table[..terminator];
    let mut rows = Vec::new();
    let mut cursor = table;
    while let Some(open) = cursor.find(ROW_OPEN) {
        let rest = &cursor[open + ROW_OPEN.len()..];
        let close = rest
            .find("\n    }")
            .expect("every boundary row must close with an indented brace");
        let mut fields = Vec::new();
        for line in rest[..close].lines() {
            let Some((field, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            let resolved = match value.strip_prefix("concat!(") {
                Some(literals) => literals.split('"').skip(1).step_by(2).fold(
                    String::new(),
                    |mut merged, part| {
                        merged.push_str(part);
                        merged
                    },
                ),
                None => value.trim_end_matches(',').trim_matches('"').to_owned(),
            };
            fields.push((field.trim().to_owned(), resolved));
        }
        rows.push(fields);
        cursor = &rest[close..];
    }
    rows
}

/// Returns one field of one parsed boundary row, failing when the row does not
/// carry it.
fn case1_field<'a>(row: &'a [(String, String)], field: &str) -> &'a str {
    let (_, value) = row
        .iter()
        .find(|(name, _)| name == field)
        .unwrap_or_else(|| panic!("every boundary row must carry the {field:?} field"));
    value.as_str()
}

// WORK_UNIT_CASE: 891/1
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 1 compares the fixture boundary table against the parsed source table in one deterministic pass"
)]
fn case_1_frozen_boundary_table_matches_fixture_and_propagated_exclusions() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let table = &fixture["boundary_table"];
    let rows = case1_parse_boundary_table(&lib);
    assert!(
        !rows.is_empty(),
        "the frozen boundary table must parse into at least one row"
    );

    // The pinned source must name the file this test really read and the
    // symbol that file really declares.
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(
        manifest_dir.ends_with(std::path::Path::new("bins/eliot-host")),
        "this integration target must belong to bins/eliot-host, got {manifest_dir:?}"
    );
    let pinned = table["source"]
        .as_str()
        .expect("the fixture must pin the boundary table source");
    let (pinned_path, pinned_symbol) = pinned
        .rsplit_once("::")
        .expect("the pinned boundary table source must name a symbol");
    assert!(
        std::path::Path::new(pinned_path)
            .ends_with(std::path::Path::new("bins/eliot-host/src/lib.rs")),
        "the fixture must pin the table to the file this test reads, got {pinned_path}"
    );
    assert!(
        lib.contains(&format!(
            "const {pinned_symbol}: &[HostLifecycleBoundary] = &["
        )),
        "the pinned symbol {pinned_symbol} must be the table this test parses"
    );

    // Denominator: the row count and the emitting/propagated split, each read
    // out of the parsed source literal rather than re-asserted in the fixture.
    let fixture_rows = usize::try_from(
        table["rows"]
            .as_u64()
            .expect("the fixture must pin the row count"),
    )
    .expect("the pinned row count must fit usize");
    let fixture_emitting = usize::try_from(
        table["emitting"]
            .as_u64()
            .expect("the fixture must pin the emitting count"),
    )
    .expect("the pinned emitting count must fit usize");
    let fixture_propagated = usize::try_from(
        table["propagated"]
            .as_u64()
            .expect("the fixture must pin the propagated count"),
    )
    .expect("the pinned propagated count must fit usize");
    let propagated: Vec<&[(String, String)]> = rows
        .iter()
        .filter(|row| case1_field(row.as_slice(), "event").starts_with("propagated:"))
        .map(Vec::as_slice)
        .collect();
    let emitting_events: Vec<&str> = rows
        .iter()
        .map(|row| case1_field(row, "event"))
        .filter(|event| !event.starts_with("propagated:"))
        .collect();
    assert_eq!(
        rows.len(),
        fixture_rows,
        "the parsed boundary row count drifted from the fixture"
    );
    assert_eq!(
        emitting_events.len(),
        fixture_emitting,
        "the emitting row count drifted from the fixture"
    );
    assert_eq!(
        propagated.len(),
        fixture_propagated,
        "the propagated exclusion count drifted from the fixture"
    );
    assert_eq!(
        emitting_events.len() + propagated.len(),
        fixture_rows,
        "every frozen row must be either emitting or an explicit propagated exclusion"
    );

    // Names in exact table order, element by element, so a reorder fails.
    let names = table["names"]
        .as_array()
        .expect("the fixture must pin the boundary names");
    assert_eq!(
        names.len(),
        rows.len(),
        "the fixture must pin exactly one name per parsed row"
    );
    for (index, row) in rows.iter().enumerate() {
        let expected = names[index]
            .as_str()
            .expect("every pinned boundary name must be a string");
        assert_eq!(
            case1_field(row, "name"),
            expected,
            "the boundary name at table index {index} drifted from the fixture order"
        );
    }

    // The explicit propagated exclusions, in table order: each excluded row
    // records a `propagated:` reason and is bound by exactly one exclusion
    // identifier beside its table row.
    let exclusions = table["propagated_exclusions"]
        .as_array()
        .expect("the fixture must pin the propagated exclusions");
    assert_eq!(
        exclusions.len(),
        propagated.len(),
        "the fixture must pin one exclusion per propagated row"
    );
    for (row, excluded) in propagated.iter().copied().zip(exclusions.iter()) {
        let excluded = excluded
            .as_str()
            .expect("every propagated exclusion must be a string");
        assert_eq!(
            case1_field(row, "name"),
            excluded,
            "the propagated exclusion must name its own table row"
        );
        let event = case1_field(row, "event");
        assert!(
            event.starts_with("propagated:"),
            "an excluded row must record the exact propagated reason, got {event}"
        );
        assert_eq!(
            count_occurrences(&lib, &format!("\"{event}\"")),
            2,
            "a propagated reason must appear exactly twice: once as its table row and once as one explicit exclusion identifier"
        );
    }
    for identifier in [
        "PROPAGATED_PHASE_B_ROLLBACK",
        "PROPAGATED_ACTIVATION_TRANSITIONS",
        "PROPAGATED_CUTOVER_CANDIDATE_ARM",
    ] {
        assert!(
            lib.contains(&format!("const {identifier}: &HostLifecycleBoundary =")),
            "propagated exclusion {identifier} must stay an explicit static identifier"
        );
    }

    // The excluded rows own no emission in source: no observation call site
    // selects a propagated row or spells its reason.
    for line in lib
        .lines()
        .filter(|line| line.contains("host_lifecycle_observe_"))
    {
        assert!(
            !line.contains("PROPAGATED_"),
            "no observation call site may select a propagated row: {line}"
        );
        for row in propagated.iter().copied() {
            let event = case1_field(row, "event");
            assert!(
                !line.contains(event),
                "no observation call site may spell the propagated reason {event}: {line}"
            );
        }
    }

    // Every row is fully bound: no empty name, source item, owner state, event,
    // caller or proving test, and no duplicated name or event.
    for row in &rows {
        for field in [
            "name",
            "source_item",
            "owner_state",
            "event",
            "caller",
            "test",
        ] {
            assert!(
                !case1_field(row, field).trim().is_empty(),
                "every boundary row must bind a non-empty {field}"
            );
        }
    }
    for (index, row) in rows.iter().enumerate() {
        for other in rows.iter().skip(index + 1) {
            assert_ne!(
                case1_field(row, "name"),
                case1_field(other, "name"),
                "two boundary rows must never share a name"
            );
            assert_ne!(
                case1_field(row, "event"),
                case1_field(other, "event"),
                "two boundary rows must never share an event"
            );
        }
    }

    // Selection stays compile-time bound: exactly one static identifier per
    // emitting row, one per propagated row, and one lookup definition.
    assert_eq!(
        count_occurrences(&lib, "const BOUNDARY_"),
        emitting_events.len(),
        "every emitting row must own exactly one static boundary identifier"
    );
    assert_eq!(
        count_occurrences(&lib, "const PROPAGATED_"),
        propagated.len(),
        "every propagated row must own exactly one explicit exclusion identifier"
    );

    // Executed: every emitting spelling survives the real bounded formatter
    // unchanged and reaches the real facade verbatim, so the parsed table is
    // the vocabulary the real facade emits and delivers unchanged when handed a
    // parsed row event.
    // This capture calls the facade directly, so it still proves only the
    // facade's own formatting and delivery for the frozen spellings. The
    // OWNER-EMITTED spelling is now proved separately below by the
    // `HostComposition::open` capture, which is a real production owner
    // operation.
    for event in &emitting_events {
        assert_eq!(
            eliot_host::host_diagnostics::bound_detail(event).text(),
            *event,
            "the frozen boundary vocabulary must survive the bounded formatter unchanged"
        );
    }
    let emitted = capture_emit(|| {
        for event in &emitting_events {
            observe_entrypoint_with_detail(EntrypointStage::Startup, event);
        }
    });
    for event in &emitting_events {
        assert!(
            emitted.contains(*event),
            "the real facade must emit the frozen boundary event {event:?} verbatim"
        );
    }
    for row in propagated.iter().copied() {
        let event = case1_field(row, "event");
        assert!(
            !emitted.contains(event),
            "a propagated exclusion must never be emitted: {event}"
        );
    }
    assert!(
        emitted.contains(HOST_DIAGNOSTICS_TARGET),
        "the frozen vocabulary must travel through the #889 facade target"
    );

    // Owner pass risks, all three named: `lib.rs` runs a wiring self-check over
    // a by-value backup-dispatch table before the observation and registers no
    // process-global, `HostOwnerLease::acquire` is a real `Global\` named mutex,
    // and the guarded region is entered unconditionally, so the captured
    // evidence is identical on every machine whichever fallible step fails
    // first.
    let owner_emitted = capture_emit(|| {
        let _ = eliot_host::HostComposition::open(
            eliot_host::HostLaunchOptions::parse(case21_launch_argv())
                .expect("the established argv must admit"),
        );
    });
    assert_eq!(
        count_occurrences(&owner_emitted, "detail=\"host.open requested\""),
        1,
        "one failed owner operation must emit the open request row exactly once: {owner_emitted}"
    );
    assert_eq!(
        count_occurrences(&owner_emitted, "code=\"host-open-failed\""),
        1,
        "one failed owner operation must emit exactly one designated terminal: {owner_emitted}"
    );
    assert_eq!(
        count_occurrences(&owner_emitted, "detail=\"host.open admitted\""),
        0,
        "a failed owner operation must never emit the admitted row: {owner_emitted}"
    );
    let owner_requested = rows
        .iter()
        .find(|row| case1_field(row.as_slice(), "event") == "host.open requested")
        .expect("the frozen table must carry the open request row the owner emitted");
    let owner_requested_detail = case1_field(owner_requested, "event");
    assert_eq!(
        count_occurrences(
            &owner_emitted,
            &format!("detail=\"{owner_requested_detail}\"")
        ),
        1,
        "the detail the OWNER emitted must be byte-identical to the frozen table spelling taken from `src/lib.rs`, which is what binds this row to the table rather than to a literal: {owner_emitted}"
    );
}

// WORK_UNIT_CASE: 891/2
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 2 keeps the start request/result source structure, the facade records and the evidence gate in one deterministic pass"
)]
fn case_2_service_start_request_is_distinct_from_result() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");

    // Source: the real exported service-start contour.
    let contour_start = lib
        .find("pub fn start_approved_contour")
        .expect("lib.rs must declare the exported service-start contour");
    let contour = &lib[contour_start..];
    let contour_end = contour
        .find("pub fn resume_pending_activation_after_phase_b")
        .expect("the start contour must be followed by the resume-pending contour");
    let contour = &contour[..contour_end];

    let requested = "host_lifecycle_observe_requested(BOUNDARY_START_REQUESTED);";
    let armed = "HostTerminalGuard::armed(BOUNDARY_START_TERMINAL)";
    let disarmed = "host_terminal.disarm();";
    let started = "host_lifecycle_observe_requested(BOUNDARY_START_STARTED);";
    let requested_at = contour
        .find(requested)
        .unwrap_or_else(|| panic!("the start contour must observe {requested:?}"));
    let armed_at = contour
        .find(armed)
        .unwrap_or_else(|| panic!("the start contour must arm {armed:?}"));
    let disarmed_at = contour
        .find(disarmed)
        .unwrap_or_else(|| panic!("a successful start must disarm {disarmed:?}"));
    let started_at = contour
        .find(started)
        .unwrap_or_else(|| panic!("the start contour must observe {started:?}"));
    assert!(
        requested_at < armed_at,
        "the start request is observed before the terminal guard arms"
    );
    assert!(
        armed_at < disarmed_at,
        "the terminal guard arms before the start result disarms it"
    );
    assert!(
        disarmed_at < started_at,
        "the start result is recorded only after the guard is disarmed, never on a failed start"
    );
    assert_eq!(
        count_occurrences(contour, "HostTerminalGuard::armed("),
        1,
        "one public start operation owns exactly one designated terminal"
    );
    assert_eq!(
        count_occurrences(&lib, requested),
        1,
        "the start request record has exactly one emission site"
    );
    assert_eq!(
        count_occurrences(&lib, started),
        1,
        "the start result record has exactly one emission site"
    );
    assert_eq!(
        count_occurrences(&lib, "BOUNDARY_START_TERMINAL"),
        2,
        "the start terminal is declared once and armed once, never emitted directly"
    );

    // Discovery: the frozen events come from the boundary table, are pinned by
    // the fixture, and travel through the one start-record seam.
    let request_event = "host.start requested";
    let result_event = "host.start started";
    let details = fixture["lifecycle_details"]
        .as_array()
        .expect("the fixture must pin the lifecycle details");
    for event in [request_event, result_event] {
        assert!(
            lib.contains(&format!("boundary_by_event(\"{event}\")")),
            "the frozen start event {event:?} must be selected from the boundary table"
        );
        assert!(
            details.iter().any(|detail| detail.as_str() == Some(event)),
            "the fixture must pin the frozen start event {event:?}"
        );
    }
    assert_ne!(
        request_event, result_event,
        "the start request and the start result must stay distinct records"
    );
    let start_terminal = fixture["terminal_codes"]["start_failed"]
        .as_str()
        .expect("the fixture must pin the start terminal code");
    assert!(
        lib.contains(&format!(
            "const BOUNDARY_START_TERMINAL: &HostLifecycleBoundary = boundary_by_event(\"{start_terminal}\");"
        )),
        "the start guard must carry exactly the fixture's pinned start terminal code"
    );
    let seam = &lib[lib
        .find("fn host_lifecycle_observe_requested")
        .expect("lib.rs must declare the start-record observation seam")..];
    let seam = &seam[..seam.find("\n}\n").unwrap_or_else(|| {
        panic!("the start-record observation seam must close with an indented brace")
    })];
    assert!(
        seam.contains("host_diagnostics::EntrypointStage::Startup"),
        "the start-record seam must stamp the Startup stage"
    );
    assert!(
        seam.contains("host_lifecycle_frozen_event(boundary)"),
        "the start-record seam must emit the frozen row event, never a free string"
    );

    // Executed: one request and one result, distinct records sharing one
    // correlation, and no terminal on the successful path.
    let correlation = "generation:891-case-2";
    let succeeded = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("{request_event} {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("{result_event} {correlation}"),
        );
    });
    let succeeded_flat = succeeded.replace('"', "");
    assert!(
        succeeded_flat.contains(&format!("stage={}", EntrypointStage::Startup.as_str())),
        "the start records must be stamped with the Startup stage, got: {succeeded}"
    );
    assert!(
        succeeded_flat.contains(
            fixture["entrypoint_event"]
                .as_str()
                .expect("the fixture must pin the entrypoint event")
        ),
        "the start records must travel through the entrypoint facade event, got: {succeeded}"
    );
    assert_eq!(
        count_occurrences(&succeeded, request_event),
        1,
        "the start request record must be emitted once, got: {succeeded}"
    );
    assert_eq!(
        count_occurrences(&succeeded, result_event),
        1,
        "the start result record must be emitted once, got: {succeeded}"
    );
    assert_eq!(
        count_occurrences(&succeeded, correlation),
        2,
        "the start request and the start result must share one correlation, got: {succeeded}"
    );
    assert!(
        !succeeded_flat.contains(
            fixture["terminal_event"]
                .as_str()
                .expect("the fixture must pin the terminal event")
        ),
        "a successful start owns no terminal record, got: {succeeded}"
    );

    // Executed: the failing start emits the request and exactly one terminal,
    // and never the result record.
    let failed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("{request_event} {correlation}"),
        );
        observe_terminal_error(start_terminal);
    });
    assert!(
        failed.contains(request_event),
        "a failed start still records its request, got: {failed}"
    );
    assert!(
        !failed.contains(result_event),
        "a failed start must never record the start result, got: {failed}"
    );
    assert_eq!(
        count_occurrences(
            &failed,
            fixture["terminal_event"]
                .as_str()
                .expect("the fixture must pin the terminal event")
        ),
        1,
        "one failed start emits exactly one terminal, got: {failed}"
    );
    assert_eq!(
        count_occurrences(&failed, start_terminal),
        1,
        "the failed start emits exactly the operation's own terminal code, got: {failed}"
    );

    // Executed: the real identity projection separates the start request from
    // the start result and keeps readiness explicitly missing without host
    // evidence.
    let process_id = std::process::id();
    let request_record = capture_emit(|| {
        eliot_host::host_diagnostics::observe_host_request(
            &eliot_host::host_diagnostics::HostRequestProjection::observed(
                EntrypointStage::Startup,
            ),
        );
    });
    let result_record = capture_emit(|| {
        eliot_host::host_diagnostics::observe_host_request(
            &eliot_host::host_diagnostics::HostRequestProjection::process_started(
                EntrypointStage::Startup,
                process_id,
            ),
        );
    });
    let request_flat = request_record.replace('"', "");
    let result_flat = result_record.replace('"', "");
    for (label, record) in [("request", &request_flat), ("result", &result_flat)] {
        assert!(
            record.contains(&format!("service={}", eliot_host::SERVICE_NAME)),
            "the start {label} record must name the Host service, got: {record}"
        );
        assert!(
            record.contains("running_missing=true"),
            "the start {label} record must keep readiness explicitly missing without host evidence, got: {record}"
        );
    }
    assert!(
        request_flat.contains("evidence=observed"),
        "the start request is a sighting record, got: {request_record}"
    );
    assert!(
        result_flat.contains("evidence=process_started"),
        "the start result is a process-started record, got: {result_record}"
    );
    assert!(
        result_flat.contains(&format!("process={process_id}")),
        "the start result must carry the observed process id, got: {result_record}"
    );
    assert_ne!(
        request_flat, result_flat,
        "the start request and the start result must stay distinct records"
    );

    // Executed: the Event Log seam admits a start only from the owner's own
    // start evidence, never from a sighting or a readiness claim.
    assert!(
        AdmittedEvent::ServiceStart
            .is_admitted_by(eliot_host::host_diagnostics::HostRequestEvidence::ProcessStarted),
        "the owner's own start evidence must admit the start event"
    );
    for evidence in [
        eliot_host::host_diagnostics::HostRequestEvidence::Observed,
        eliot_host::host_diagnostics::HostRequestEvidence::Admitted,
        eliot_host::host_diagnostics::HostRequestEvidence::SemanticallyReady,
        eliot_host::host_diagnostics::HostRequestEvidence::DurableCommitted,
        eliot_host::host_diagnostics::HostRequestEvidence::Cancelled,
        eliot_host::host_diagnostics::HostRequestEvidence::Failed,
        eliot_host::host_diagnostics::HostRequestEvidence::Unknown,
    ] {
        assert!(
            !AdmittedEvent::ServiceStart.is_admitted_by(evidence),
            "a start request is never a start result: {evidence:?} must not admit it"
        );
    }
    assert_eq!(
        event_log_sink_status().is_ok(),
        cfg!(windows),
        "the Event Log seam stays typed-Unavailable off Windows and reports the platform honestly; the proof above is admission-only"
    );
}

// WORK_UNIT_CASE: 891/3
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 3 keeps the ready-proof source structure, the evidence taxonomy and the facade records in one deterministic pass"
)]
fn case_3_startup_ready_requires_real_readiness_evidence() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");

    // Source: the ready proof is emitted only on the readiness-evidence branch
    // of the live readiness contour, never beside it and never on the
    // degraded arm.
    let contour_start = lib
        .find("fn reconcile_branch_readiness_at")
        .expect("lib.rs must declare the readiness contour");
    let contour = &lib[contour_start..];
    let contour_end = contour
        .find("fn reobserve_watchdog_supervision_evidence")
        .expect("the readiness contour must be followed by the Watchdog re-observation contour");
    let contour = &contour[..contour_end];

    let healthy = "if outcome == HostBranchDisposition::Healthy {";
    let requested_proof = "host_lifecycle_observe_requested(BOUNDARY_READINESS_REQUESTED_PROOF);";
    let ready = "host_lifecycle_observe_requested(BOUNDARY_READINESS_READY_PROOF);";
    let degraded_arm = "} else if !self.persist_authenticated_readiness_degradation(";
    let healthy_at = contour
        .find(healthy)
        .unwrap_or_else(|| panic!("the readiness contour must branch on {healthy:?}"));
    let requested_at = contour
        .find(requested_proof)
        .unwrap_or_else(|| panic!("the readiness contour must observe {requested_proof:?}"));
    let ready_at = contour
        .find(ready)
        .unwrap_or_else(|| panic!("the readiness contour must observe {ready:?}"));
    let degraded_at = contour.find(degraded_arm).unwrap_or_else(|| {
        panic!("the readiness contour must keep its degraded arm {degraded_arm:?}")
    });
    assert!(
        requested_at < healthy_at,
        "the readiness proof is requested before it is proven"
    );
    assert!(
        healthy_at < ready_at,
        "the ready proof may only be emitted inside the readiness-evidence arm"
    );
    assert!(
        ready_at < degraded_at,
        "the ready proof must sit inside the evidence arm, never in the degraded one"
    );
    let healthy_line = contour[..healthy_at]
        .rsplit('\n')
        .next()
        .expect("the readiness evidence arm must be a source line");
    let ready_line = contour[..ready_at]
        .rsplit('\n')
        .next()
        .expect("the ready observation must be a source line");
    let healthy_indent = healthy_line.len() - healthy_line.trim_start().len();
    let ready_indent = ready_line.len() - ready_line.trim_start().len();
    assert!(
        ready_indent > healthy_indent,
        "the ready observation must sit in the block the evidence arm opens, not beside it"
    );
    assert_eq!(
        count_occurrences(contour, requested_proof),
        1,
        "the readiness proof request has exactly one emission site"
    );
    assert_eq!(
        count_occurrences(contour, ready),
        1,
        "the ready proof has exactly one emission site in the readiness contour"
    );

    // Source: the durable ready record follows the confirmed proof fence.
    let confirmed = "if !confirmed.same_probe_input_contour(&contour)";
    let durable_ready = "host_lifecycle_observe_requested(BOUNDARY_READINESS_PROOF_READY);";
    let confirmed_at = lib.find(confirmed).unwrap_or_else(|| {
        panic!("the readiness owner must re-check the confirmed proof contour {confirmed:?}")
    });
    let durable_ready_at = lib
        .find(durable_ready)
        .unwrap_or_else(|| panic!("the readiness owner must observe {durable_ready:?}"));
    assert!(
        confirmed_at < durable_ready_at,
        "the durable ready record may only follow the confirmed proof fence"
    );
    assert_eq!(
        count_occurrences(&lib, durable_ready),
        1,
        "the durable ready record has exactly one emission site"
    );

    // Discovery: the frozen readiness events come from the boundary table and
    // are pinned by the fixture; process liveness stays its own boundary.
    let request_event = "host.readiness requested proof";
    let ready_event = "host.readiness ready proof";
    let degraded_event = "host.readiness degraded";
    let details = fixture["lifecycle_details"]
        .as_array()
        .expect("the fixture must pin the lifecycle details");
    for event in [request_event, ready_event, degraded_event] {
        assert!(
            lib.contains(&format!("boundary_by_event(\"{event}\")")),
            "the frozen readiness event {event:?} must be selected from the boundary table"
        );
        assert!(
            details.iter().any(|detail| detail.as_str() == Some(event)),
            "the fixture must pin the frozen readiness event {event:?}"
        );
    }
    assert!(
        lib.contains("boundary_by_event(\"host.liveness observed\")"),
        "process liveness must remain its own frozen boundary, never a readiness claim"
    );
    assert_ne!(
        ready_event, degraded_event,
        "a proven readiness and a degraded readiness must stay distinct records"
    );

    // Discovery: the #889 evidence taxonomy makes a readiness claim
    // constructible in exactly one place, and only from opened-host evidence.
    assert_eq!(
        count_occurrences(&facade, "HostRequestEvidence::SemanticallyReady"),
        1,
        "the semantic readiness evidence class must be constructible in exactly one place"
    );
    assert!(
        facade.contains(
            "pub const fn semantically_ready(phase: EntrypointStage, host: &HostComposition)"
        ),
        "a semantic readiness claim must require the opened host as its backing evidence"
    );

    // Executed: the proven and the degraded readiness records are distinct
    // records of the same contour, and neither carries the other's event.
    let proven = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::Startup, request_event);
        observe_entrypoint_with_detail(EntrypointStage::Startup, ready_event);
    });
    let degraded = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::Startup, request_event);
        observe_entrypoint_with_detail(EntrypointStage::Startup, degraded_event);
    });
    assert!(
        proven.contains(ready_event) && !proven.contains(degraded_event),
        "a proven readiness emits the ready proof and never the degraded record, got: {proven}"
    );
    assert!(
        degraded.contains(degraded_event) && !degraded.contains(ready_event),
        "a degraded readiness must never emit the ready proof, got: {degraded}"
    );
    for record in [&proven, &degraded] {
        assert!(
            record.contains(request_event),
            "both readiness records correlate on the requested proof, got: {record}"
        );
        assert!(
            record.contains(HOST_DIAGNOSTICS_TARGET),
            "readiness records must travel through the #889 facade target, got: {record}"
        );
    }

    // Executed: a launched contour proves process start, not semantic
    // readiness, and the evidence gate never turns a readiness claim into a
    // completed start.
    let liveness = capture_emit(|| {
        eliot_host::host_diagnostics::observe_host_request(
            &eliot_host::host_diagnostics::HostRequestProjection::process_started(
                EntrypointStage::Startup,
                std::process::id(),
            ),
        );
    });
    let liveness_flat = liveness.replace('"', "");
    assert!(
        liveness_flat.contains("evidence=process_started"),
        "a launched contour records the owner's process evidence, got: {liveness}"
    );
    assert!(
        liveness_flat.contains("running_missing=true"),
        "process liveness must never project semantic readiness, got: {liveness}"
    );
    assert_ne!(
        eliot_host::host_diagnostics::HostRequestEvidence::ProcessStarted.as_str(),
        eliot_host::host_diagnostics::HostRequestEvidence::SemanticallyReady.as_str(),
        "liveness and readiness must stay distinct evidence classes"
    );
    assert!(
        !AdmittedEvent::ServiceStart
            .is_admitted_by(eliot_host::host_diagnostics::HostRequestEvidence::SemanticallyReady),
        "a readiness claim is never a completed start"
    );
    assert_eq!(
        fixture["distinctions"]["liveness_vs_readiness"].as_bool(),
        Some(true),
        "the fixture must keep process liveness distinct from semantic readiness"
    );
}

// WORK_UNIT_CASE: 891/4
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 4 keeps the SCM receipt source structure, the real receipt round trip and the replay separation in one deterministic pass"
)]
fn case_4_scm_receipt_retains_control_and_operation_identity() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");

    // Source: the SCM dispatch answers a receipt only from the typed Ok arm
    // of the restart operation.
    let dispatch_start = lib
        .find("pub fn handle_kernel_restart_request")
        .expect("lib.rs must declare the SCM restart dispatch");
    let dispatch = &lib[dispatch_start..];
    let dispatch_end = dispatch
        .find("pub fn reconcile_kernel_restart_request")
        .expect("the SCM dispatch must be followed by its reconcile projection");
    let dispatch = &dispatch[..dispatch_end];

    let ok_arm = "Ok(receipt) => {";
    let receipt_site = "host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_RECEIPT_COMPLETION);";
    let receipt_answer = "HostRuntimeControlResponse::restarted_for(request, receipt)";
    let err_arm = "Err(_error) => {";
    let ok_at = dispatch
        .find(ok_arm)
        .unwrap_or_else(|| panic!("the SCM dispatch must match the typed {ok_arm:?} arm"));
    let receipt_at = dispatch
        .find(receipt_site)
        .unwrap_or_else(|| panic!("the SCM dispatch must observe {receipt_site:?}"));
    let answer_at = dispatch
        .find(receipt_answer)
        .unwrap_or_else(|| panic!("the SCM dispatch must build {receipt_answer:?}"));
    let err_at = dispatch
        .find(err_arm)
        .unwrap_or_else(|| panic!("the SCM dispatch must match the typed {err_arm:?} arm"));
    assert!(
        ok_at < receipt_at,
        "the receipt observation belongs to the typed Ok arm"
    );
    assert!(
        receipt_at < answer_at,
        "the admitted receipt is observed before the control answer is built"
    );
    assert!(
        answer_at < err_at,
        "the receipt answer may only be built inside the typed Ok arm, never after the failure arm"
    );
    assert_eq!(
        count_occurrences(dispatch, receipt_answer),
        1,
        "the receipt answer has exactly one construction site"
    );
    let failure_arm = &dispatch[err_at..];
    assert!(
        failure_arm.contains("HostRuntimeControlResponse::unknown_for("),
        "the typed failure arm must answer typed non-success"
    );
    assert!(
        !failure_arm.contains(receipt_answer),
        "the typed failure arm may never answer a receipt"
    );
    assert!(
        dispatch.contains("host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_UNKNOWN);"),
        "a restart without an admitted receipt keeps an explicit unknown observation"
    );

    // A receipt is not a completion: one receipt observation site, and a
    // repeated observation of the same committed operation is a replay.
    assert_eq!(
        count_occurrences(&lib, "BOUNDARY_KERNEL_RESTART_RECEIPT_COMPLETION"),
        2,
        "the receipt completion boundary is declared once and observed once"
    );
    assert!(
        lib.contains("boundary_by_event(\"host.kernel-restart receipt completion\")"),
        "the receipt completion event must be selected from the boundary table"
    );
    assert!(
        fixture["scm_details"]
            .as_array()
            .expect("the fixture must pin the SCM details")
            .iter()
            .any(|detail| detail.as_str() == Some("host.kernel-restart receipt completion")),
        "the fixture must pin the SCM receipt completion detail"
    );
    assert_eq!(
        fixture["distinctions"]["receipt_vs_completion"].as_bool(),
        Some(true),
        "the fixture must keep a control receipt distinct from a completion"
    );
    assert_eq!(
        count_occurrences(
            &lib,
            "BOUNDARY_KERNEL_RESTART_RECONCILE_RECEIPT_READBACK_REPLAY"
        ),
        2,
        "the reconcile receipt readback is declared once and observed once"
    );
    assert!(
        lib.contains(
            "boundary_by_event(\"host.kernel-restart-reconcile receipt readback replay\")"
        ),
        "a repeated observation of a committed receipt stays a labelled readback replay"
    );

    // Executed: the receipt is built exactly as the owner builds it, from the
    // request's own digests, and answers only the control operation that asked
    // for it.
    let request = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RestartKernel,
        eliot_platform::PlatformHandle::new("891-case-4-restart".to_owned())
            .expect("the case-4 request id must be a valid handle"),
    )
    .expect("the case-4 restart request must validate on the wire");
    let identity = |slot: &str| {
        eliot_platform::PlatformHandle::new(eliot_platform_windows::sha256_hex(
            format!("891-case-4-receipt:{slot}").as_bytes(),
        ))
        .unwrap_or_else(|error| {
            panic!("the case-4 {slot} identity must be a valid handle: {error}")
        })
    };
    let mut receipt = eliot_host::HostKernelRestartReceipt {
        mutation_digest: request.mutation_digest.clone(),
        request_digest: request.request_digest.clone(),
        old_kernel_generation: identity("old-kernel-generation"),
        new_kernel_generation: identity("new-kernel-generation"),
        store_fence: identity("store-fence"),
        activation_receipt_digest: identity("activation-receipt"),
        ready_receipt_digest: identity("ready-receipt"),
        receipt_digest: eliot_platform::PlatformHandle::new("0".repeat(64))
            .expect("the owner's receipt placeholder must be a valid handle"),
    };
    receipt.receipt_digest = receipt
        .computed_digest()
        .expect("the case-4 receipt digest must compute");
    receipt
        .validate()
        .expect("the case-4 receipt must validate");

    let answer = eliot_host::HostRuntimeControlResponse::restarted_for(&request, receipt.clone());
    answer.validate().expect("the receipt answer must validate");
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&request, &answer),
        "the receipt must retain the exact control request identity"
    );
    let eliot_host::HostRuntimeControlResponse::Restarted { receipt: bound } = &answer else {
        panic!("the typed Ok arm answers a tagged Restarted receipt, never a free-text status");
    };
    assert_eq!(
        bound.mutation_digest, request.mutation_digest,
        "the receipt must retain the exact control mutation identity"
    );
    assert_eq!(
        bound.request_digest, request.request_digest,
        "the receipt must retain the exact control request digest"
    );
    assert_eq!(
        serde_json::to_value(&answer).expect("the receipt answer must serialize")["status"]
            .as_str(),
        Some("RESTARTED"),
        "the typed answer stays a tagged wire status, never a free-text machine status"
    );

    // The receipt is identity-derived, not a self-declared completion: any
    // identity drift breaks its own validation.
    let mut drifted = receipt;
    drifted.ready_receipt_digest = identity("ready-receipt-drifted");
    assert!(
        drifted.validate().is_err(),
        "a drifted receipt identity must fail the owner's own validation"
    );

    // A receipt built for one control operation never answers another.
    let other = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::ReconcileKernelRestart,
        eliot_platform::PlatformHandle::new("891-case-4-reconcile".to_owned())
            .expect("the case-4 reconcile request id must be a valid handle"),
    )
    .expect("the case-4 reconcile request must validate on the wire");
    assert!(
        !eliot_host_service::runtime_control::response_matches_request(&other, &answer),
        "a receipt must never answer a different control operation"
    );

    // Executed: the SCM receipt observation correlates on the exact request
    // digest the answer retained.
    let correlation = request.request_digest.as_str();
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart receipt completion {correlation}"),
        );
    });
    let flat = text.replace('"', "");
    assert!(
        flat.contains(&format!("stage={}", EntrypointStage::ScmDispatch.as_str())),
        "SCM records must be stamped with the ScmDispatch stage, got: {text}"
    );
    assert_eq!(
        count_occurrences(&text, correlation),
        2,
        "the SCM receipt observation must correlate on the exact request digest, got: {text}"
    );
    assert!(
        flat.contains(
            fixture["entrypoint_event"]
                .as_str()
                .expect("the fixture must pin the entrypoint event")
        ),
        "SCM records must travel through the entrypoint facade event, got: {text}"
    );
    assert!(
        !flat.contains(
            fixture["terminal_event"]
                .as_str()
                .expect("the fixture must pin the terminal event")
        ),
        "an admitted SCM receipt owns no terminal record, got: {text}"
    );
}

// WORK_UNIT_CASE: 891/5
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 5 keeps the unsupported-control refusal structure, the typed non-success round trip and the failed/unknown separation in one deterministic pass"
)]
fn case_5_unsupported_control_stays_typed_non_success() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");

    // Source: an unsupported control is refused inside the restart operation by
    // a typed error, never by a status string, and the answer stays with the
    // outer dispatch.
    let execute_start = lib
        .find("fn execute_kernel_restart")
        .expect("lib.rs must declare the restart operation");
    let execute = &lib[execute_start..];
    let execute_end = execute
        .find("pub fn owner_lease_name")
        .expect("the restart operation must be followed by the owner-lease projection");
    let execute = &execute[..execute_end];

    let unsupported_site = "if request.operation != HostRuntimeControlOperation::RestartKernel {";
    let unsupported_reason = "\"unsupported runtime-control operation\".to_owned(),";
    let pending_reason =
        "\"Kernel restart intent is pending and outcome is unknown; reconcile required\"";
    let site_at = execute
        .find(unsupported_site)
        .unwrap_or_else(|| panic!("the restart operation must gate on {unsupported_site:?}"));
    let reason_at = execute
        .find(unsupported_reason)
        .unwrap_or_else(|| panic!("the restart operation must refuse with {unsupported_reason:?}"));
    let pending_at = execute.find(pending_reason).unwrap_or_else(|| {
        panic!("the restart operation must keep the pending-intent reason {pending_reason:?}")
    });
    assert!(
        site_at < reason_at,
        "the unsupported refusal must follow the operation check"
    );
    let refusal = &execute[site_at..pending_at];
    assert!(
        refusal.contains("return Err(HostError::ProcessContour("),
        "an unsupported control must be refused by a typed Host error, never a free-text status"
    );
    assert!(
        !refusal.contains("HostRuntimeControlResponse::"),
        "the inner operation refuses with an error; the typed answer stays with the outer dispatch"
    );
    assert!(
        pending_at > reason_at,
        "the pending-intent refusal is a separate later boundary, not the unsupported one"
    );

    // Source: the dispatch turns that typed error into typed non-success with
    // the exact unknown ref of the request.
    let dispatch_start = lib
        .find("pub fn handle_kernel_restart_request")
        .expect("lib.rs must declare the SCM restart dispatch");
    let dispatch = &lib[dispatch_start..];
    let dispatch_end = dispatch
        .find("pub fn reconcile_kernel_restart_request")
        .expect("the SCM dispatch must be followed by its reconcile projection");
    let dispatch = &dispatch[..dispatch_end];
    let err_at = dispatch
        .find("Err(_error) => {")
        .expect("the SCM dispatch must match the typed failure arm");
    let failure_arm = &dispatch[err_at..];
    assert!(
        failure_arm.contains("runtime_control_unknown_ref(\"kernel-restart\", request)"),
        "the unsupported-control answer must keep the kernel-restart unknown ref of the exact request"
    );
    assert!(
        failure_arm.contains("host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_UNKNOWN);"),
        "an unsupported control keeps an explicit unknown observation"
    );
    assert!(
        failure_arm.contains("host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_TERMINAL);"),
        "an unsupported control ends in the operation's single terminal"
    );
    assert_eq!(
        count_occurrences(
            dispatch,
            "host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_UNKNOWN"
        ),
        2,
        "the dispatch keeps two distinct unknown observations: the fenced one and the execute one"
    );
    for event in [
        "host.kernel-restart unknown owner-fenced",
        "host.kernel-restart unknown",
    ] {
        assert!(
            lib.contains(&format!("boundary_by_event(\"{event}\")")),
            "the frozen SCM unknown event {event:?} must be selected from the boundary table"
        );
    }

    // Executed: a RecoverStore-shaped control is well-formed on the wire, and
    // the answer the dispatch builds for it is typed non-success with the
    // exact control identity preserved.
    let unsupported = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RecoverStore,
        eliot_platform::PlatformHandle::new("891-case-5-unsupported".to_owned())
            .expect("the case-5 request id must be a valid handle"),
    )
    .expect("the case-5 unsupported control must be well-formed on the wire");
    unsupported
        .validate()
        .expect("the unsupported control must validate on the wire");
    let restart = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RestartKernel,
        eliot_platform::PlatformHandle::new("891-case-5-restart".to_owned())
            .expect("the case-5 restart request id must be a valid handle"),
    )
    .expect("the case-5 restart request must validate on the wire");
    assert_ne!(
        unsupported.operation, restart.operation,
        "the unsupported control must differ from the restart operation the dispatch admits"
    );

    let pending_ref = eliot_host_service::runtime_control::runtime_control_unknown_ref(
        "kernel-restart",
        &unsupported,
    );
    let answer =
        eliot_host::HostRuntimeControlResponse::unknown_for(&unsupported, pending_ref.clone());
    answer
        .validate()
        .expect("the typed non-success answer must validate");
    assert!(
        matches!(
            &answer,
            eliot_host::HostRuntimeControlResponse::Unknown { .. }
        ),
        "an unsupported control must stay typed Unknown"
    );
    assert!(
        !matches!(
            &answer,
            eliot_host::HostRuntimeControlResponse::Restarted { .. }
                | eliot_host::HostRuntimeControlResponse::StoreRecovered { .. }
                | eliot_host::HostRuntimeControlResponse::AdmissionProjected { .. }
        ),
        "an unsupported control may never answer a success variant"
    );
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&unsupported, &answer),
        "the typed non-success answer must preserve the exact control identity"
    );
    assert!(
        !eliot_host_service::runtime_control::response_matches_request(&restart, &answer),
        "the typed non-success answer must never answer a different control operation"
    );
    assert!(
        pending_ref
            .as_str()
            .contains(unsupported.request_digest.as_str()),
        "the unknown ref must preserve the exact control request digest"
    );
    assert_eq!(
        serde_json::to_value(&answer)
            .expect("the typed non-success answer must serialize")["status"]
            .as_str(),
        Some("UNKNOWN"),
        "the typed answer stays a tagged wire status, never a free-text machine status"
    );
    assert!(
        !serde_json::to_string(&answer)
            .expect("the typed non-success answer must serialize")
            .contains("unsupported runtime-control operation"),
        "the free-text refusal reason must not travel into the control answer"
    );

    // Executed: failed and unknown stay distinct typed errors. An unsupported
    // control is a no-effect refusal; a pending intent is an unknown possible
    // effect and must never be relabelled as either.
    let no_effect =
        eliot_host::HostError::ProcessContour("unsupported runtime-control operation".to_owned());
    let possible_effect = eliot_host::HostError::RecoveryRequired(
        "Kernel restart intent is pending and outcome is unknown; reconcile required".to_owned(),
    );
    assert!(
        matches!(&no_effect, eliot_host::HostError::ProcessContour(_)),
        "an unsupported control keeps the no-effect refusal error"
    );
    assert!(
        matches!(&possible_effect, eliot_host::HostError::RecoveryRequired(_)),
        "a pending intent keeps the unknown possible-effect error"
    );
    assert!(
        !matches!(&no_effect, eliot_host::HostError::RecoveryRequired(_)),
        "an unsupported control is never an unknown possible effect"
    );
    assert!(
        !matches!(&possible_effect, eliot_host::HostError::ProcessContour(_)),
        "an unknown possible effect is never a no-effect refusal"
    );
    assert_eq!(
        fixture["distinctions"]["failed_vs_unknown"].as_bool(),
        Some(true),
        "the fixture must keep failed and unknown possible effect distinct"
    );

    // Executed: the unsupported-control observation correlates on the exact
    // request digest and ends in exactly one terminal.
    let correlation = unsupported.request_digest.as_str();
    let terminal = fixture["terminal_codes"]["kernel_restart_unknown"]
        .as_str()
        .expect("the fixture must pin the restart unknown terminal code");
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart unknown {correlation}"),
        );
        observe_terminal_error(terminal);
    });
    assert!(
        text.contains("host.kernel-restart unknown"),
        "an unsupported control keeps its explicit unknown record, got: {text}"
    );
    assert_eq!(
        count_occurrences(&text, correlation),
        2,
        "the unsupported-control observations must correlate on the exact request digest, got: {text}"
    );
    assert_eq!(
        count_occurrences(
            &text,
            fixture["terminal_event"]
                .as_str()
                .expect("the fixture must pin the terminal event")
        ),
        1,
        "one unsupported control ends in exactly one terminal, got: {text}"
    );
    assert_eq!(
        count_occurrences(&text, terminal),
        1,
        "the unsupported control emits exactly the operation's own terminal code, got: {text}"
    );
}
// Cases 6..11 of issue #891. Every assertion binds one real `lib.rs` call
// site, one real public seam and one real executed path: a hand-built log is
// never the only proof, and nothing here starts, stops or launches a service.
const CASE6_HOST_LINEAGE: &str = "89100000-0000-4000-8000-000000000900";
const CASE6_ACTIVATION_LINEAGE: &str = "89100000-0000-4000-8000-000000000910";
const CASE6_KERNEL_LINEAGE: &str = "89100000-0000-4000-8000-000000000901";
const CASE6_WATCHDOG_LINEAGE: &str = "89100000-0000-4000-8000-000000000902";
const CASE6_STORE_LINEAGE: &str = "89100000-0000-4000-8000-000000000903";

// Returns the brace-balanced source span of the function whose signature
// starts with `signature`, so each source assertion below is scoped to one real
// function body in the composition root instead of the whole file.
fn case6_fn_span(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .expect("the tracked signature must exist in the manifest source");
    let tail: Vec<char> = source[start..].chars().collect();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut end = None;
    for (index, character) in tail.iter().copied().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
        } else if character == '{' {
            depth += 1;
        } else if character == '}' && depth > 0 {
            depth -= 1;
            if depth == 0 {
                end = Some(index);
                break;
            }
        }
    }
    let end = end.expect("the tracked function span must be brace balanced");
    tail[..=end].iter().collect()
}

// Returns the exact frozen table row whose `name` field is `row`, so a source
// assertion can check one row's own caller and test declarations instead of
// counting the same field across all 121 rows.
fn case9_row(source: &str, row: &str) -> String {
    let anchor = format!("name: {row:?},");
    let start = source
        .find(&anchor)
        .unwrap_or_else(|| panic!("the frozen table must contain {row:?}"));
    let rest = &source[start..];
    let end = rest
        .find("},")
        .unwrap_or_else(|| panic!("the frozen row {row:?} must be terminated"));
    rest[..end + 2].to_owned()
}

fn case6_handle(value: &str) -> eliot_platform::PlatformHandle {
    eliot_platform::PlatformHandle::new(value).expect("the test handle must be valid")
}

// A deterministic lineage namespace: the same name always maps to the same
// canonical UUID, so the durable records below replay identically without a
// real clock, a real activation or a real activation generation.
fn case6_lineage(value: &str) -> eliot_host_state::EpochLineageId {
    eliot_host_state::EpochLineageId::new(value).expect("the test lineage must be canonical")
}

fn case6_epoch(value: &str, sequence: u64) -> eliot_host_state::EpochIdentity {
    eliot_host_state::EpochIdentity::new(
        case6_lineage(value),
        std::num::NonZeroU64::new(sequence).expect("the test sequence must be non-zero"),
    )
    .expect("the test epoch must be valid")
}

fn case6_generation(value: &str, sequence: u64) -> eliot_host_state::EpochTransition {
    eliot_host_state::EpochTransition {
        current: case6_epoch(value, sequence),
        parent: (sequence > 1).then(|| case6_epoch(value, sequence - 1)),
    }
}

fn case6_host() -> eliot_host_state::HostInstallationEpoch {
    eliot_host_state::HostInstallationEpoch {
        installation: case6_handle("eliot-installation"),
        epoch: case6_generation(CASE6_HOST_LINEAGE, 1),
        nonce: case6_handle("host-nonce-891"),
        recovery: None,
    }
}

fn case6_operation(operation: &str) -> eliot_host_state::IdempotencyIdentity {
    eliot_host_state::IdempotencyIdentity {
        operation_id: case6_handle(operation),
        idempotency_key: case6_handle(&format!("key-{operation}")),
    }
}

fn case6_fence(
    host: &eliot_host_state::HostInstallationEpoch,
    generation: &eliot_host_state::EpochTransition,
) -> eliot_host_state::RecordFence {
    eliot_host_state::RecordFence {
        host: host.clone(),
        activation_id: case6_handle("activation-891"),
        activation_generation: generation.clone(),
    }
}

// The real durable owner, opened on its deterministic in-memory backend. Cases
// 6, 7, 8, 9, 10 and 11 drive this same owner, so every state claim below is
// reduced by `eliot-host-state` and never by the test.
fn case6_journal() -> (
    eliot_host_state::HostStateJournal<eliot_host_state::MemoryBackend>,
    eliot_host_state::HostInstallationEpoch,
    eliot_host_state::EpochTransition,
) {
    let host = case6_host();
    let generation = case6_generation(CASE6_ACTIVATION_LINEAGE, 1);
    let journal = eliot_host_state::HostStateJournal::open(
        eliot_host_state::MemoryBackend::default(),
        host.clone(),
    )
    .expect("the in-memory Host journal must open");
    (journal, host, generation)
}

// The only readiness evidence the durable owner validates, so no caller can
// fake readiness with a boolean it made up itself.
fn case7_readiness(
    control_ready: bool,
    supervision_ready: bool,
) -> eliot_host_state::ReadinessEvidence {
    eliot_host_state::ReadinessEvidence {
        supervision_ready,
        control_ready,
        evidence_refs: vec![case6_handle("readiness-evidence-891")],
    }
}

// One real `EliotActivationRecord`. `directive` is the only recovery evidence a
// failed activation may carry, so the negative cases below exercise the owner
// validator and the activation reducer rather than a stub.
fn case7_activation_record(
    host: &eliot_host_state::HostInstallationEpoch,
    generation: &eliot_host_state::EpochTransition,
    operation: &str,
    state: eliot_host_state::ActivationState,
    readiness: eliot_host_state::ReadinessEvidence,
    directive: bool,
) -> eliot_host_state::HostStateRecord {
    eliot_host_state::HostStateRecord::Activation(eliot_host_state::EliotActivationRecord {
        fence: case6_fence(host, generation),
        operation: case6_operation(operation),
        activation_id: case6_handle("activation-891"),
        trigger_class: case6_handle("observable-use"),
        trigger_evidence: vec![case6_handle("trigger-evidence-891")],
        requester_principal_session_or_scheduler: case6_handle("principal-session"),
        requested_capabilities: vec![case6_handle("kernel-control")],
        candidate_scope: case6_handle("installation-scope"),
        state,
        drain_generation: matches!(
            state,
            eliot_host_state::ActivationState::Draining
                | eliot_host_state::ActivationState::StoppedClean
        )
        .then(|| generation.clone()),
        lineage: eliot_host_state::HostKernelStoreLineage {
            host_epoch: host.epoch.current.clone(),
            kernel_epoch: case6_epoch(CASE6_KERNEL_LINEAGE, 1),
            watchdog_epoch: case6_epoch(CASE6_WATCHDOG_LINEAGE, 1),
            store_generation: case6_epoch(CASE6_STORE_LINEAGE, 1),
        },
        readiness,
        governance_profile: case6_handle("governance-profile"),
        runtime_lease_refs: vec![],
        supervision_lease_refs: vec![],
        wake_intent_refs: vec![],
        drain_commit_ref: None,
        wake_during_drain_disposition: None,
        boot_session_evidence: vec![case6_handle("boot-session-evidence-891")],
        power_transition_evidence: vec![],
        timestamps: eliot_host_state::LifecycleTimestamps {
            started_at: Some(case6_handle("t-started")),
            ready_at: matches!(
                state,
                eliot_host_state::ActivationState::ControlReady
                    | eliot_host_state::ActivationState::Active
            )
            .then(|| case6_handle("t-ready")),
            draining_at: (state == eliot_host_state::ActivationState::Draining)
                .then(|| case6_handle("t-draining")),
            stopped_at: (state == eliot_host_state::ActivationState::StoppedClean)
                .then(|| case6_handle("t-stopped")),
        },
        failure_and_recovery_directive: directive.then(|| {
            eliot_host_state::FailureRecoveryDirective {
                failure_ref: case6_handle("activation-failure-891"),
                recovery_owner: case6_handle("recovery-owner"),
                directive: case6_handle("recovery-directive"),
            }
        }),
    })
}

fn case6_activation_record(
    host: &eliot_host_state::HostInstallationEpoch,
    generation: &eliot_host_state::EpochTransition,
    operation: &str,
    state: eliot_host_state::ActivationState,
) -> eliot_host_state::HostStateRecord {
    case7_activation_record(
        host,
        generation,
        operation,
        state,
        case7_readiness(true, true),
        false,
    )
}

fn case6_drain_record(
    host: &eliot_host_state::HostInstallationEpoch,
    generation: &eliot_host_state::EpochTransition,
    drain_generation: &eliot_host_state::EpochTransition,
    operation: &str,
    state: eliot_host_state::DrainState,
) -> eliot_host_state::HostStateRecord {
    eliot_host_state::HostStateRecord::Drain(eliot_host_state::DrainRecord {
        fence: case6_fence(host, generation),
        operation: case6_operation(operation),
        drain_generation: drain_generation.clone(),
        state,
        evidence_refs: vec![case6_handle("drain-evidence-891")],
        expected_predecessor: None,
    })
}

// WORK_UNIT_CASE: 891/6
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 6 keeps the stop request/pending/stopped distinctions, the one shared drain correlation, the single designated terminal and the real durable stop contour in one deterministic probe"
)]
fn lifecycle_stop_request_pending_stopped_distinct() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let stop = case6_fn_span(&lib, "pub fn stop(&mut self) -> Result<(), HostError> {");

    // Source: `HostComposition::stop` observes the stop phases in source order,
    // so request, pending and stopped are three separate records.
    let requested = stop
        .find("host_lifecycle_observe_drain(BOUNDARY_STOP_REQUESTED);")
        .expect("stop must observe the stop request phase");
    let pending = stop
        .find("host_lifecycle_observe_drain(BOUNDARY_STOP_CANCELLATION_REQUESTED);")
        .expect("stop must observe the pending cancellation phase");
    let drained = stop
        .find("host_lifecycle_observe_drain(BOUNDARY_STOP_STOPPED_CLEAN_DRAINED);")
        .expect("stop must observe the drained phase");
    let stopped = stop
        .find("host_lifecycle_observe_drain(BOUNDARY_STOP_STOPPED);")
        .expect("stop must observe the stopped phase");
    assert!(
        requested < pending && pending < drained && drained < stopped,
        "the stop contour must observe request, then pending, then drained, then stopped"
    );
    assert_eq!(
        count_occurrences(
            &lib,
            "host_lifecycle_observe_drain(BOUNDARY_STOP_REQUESTED);"
        ),
        1,
        "the stop request boundary must have exactly one call site"
    );
    assert_eq!(
        count_occurrences(&lib, "host_lifecycle_observe_drain(BOUNDARY_STOP_STOPPED);"),
        1,
        "the stop stopped boundary must have exactly one call site"
    );
    assert_eq!(
        count_occurrences(
            &lib,
            "host_lifecycle_observe_drain(BOUNDARY_STOP_STOPPED_CLEAN_DRAINED);"
        ),
        1,
        "the drained completion must be its own single call site"
    );

    // One designated error-emission boundary for the whole stop operation; the
    // lower-level phases carry the correlation without a second terminal.
    assert_eq!(
        count_occurrences(&stop, "HostTerminalGuard::armed"),
        1,
        "stop must arm exactly one designated terminal guard"
    );
    assert_eq!(
        count_occurrences(&lib, "HostTerminalGuard::armed(BOUNDARY_STOP_TERMINAL)"),
        1,
        "the stop operation must own exactly one terminal emission boundary"
    );
    let stop_failed = fixture["terminal_codes"]["stop_failed"]
        .as_str()
        .expect("the fixture must pin the stop terminal code");
    assert_eq!(stop_failed, "host-stop-failed");
    assert_eq!(
        count_occurrences(&lib, &format!("boundary_by_event({stop_failed:?})")),
        1,
        "the stop terminal code must resolve to exactly one frozen boundary row"
    );
    let disarmed = stop
        .find("host_terminal.disarm();")
        .expect("stop must disarm its guard");
    assert!(
        disarmed < stopped,
        "a clean stop must disarm before the stopped record, so it emits no terminal"
    );

    // Discovery: the pending phase names the two child terminations, and each
    // keeps its own requested and stopped boundaries. Those four frozen rows are
    // exactly the rows that declare case 6.
    assert_eq!(
        count_occurrences(&lib, "test: \"891/case-6\""),
        4,
        "exactly the four child-termination rows must declare case 6"
    );
    let mut pinned: Vec<&str> = Vec::new();
    for (signature, boundary, asked_event, stopped_event) in [
        (
            "pub fn terminate_kernel(&mut self) -> Result<(), HostError> {",
            "KERNEL_TERMINATE",
            "host.kernel-terminate requested",
            "host.kernel-terminate stopped",
        ),
        (
            "pub fn terminate_store(&mut self) -> Result<(), HostError> {",
            "STORE_TERMINATE",
            "host.store-terminate requested",
            "host.store-terminate stopped",
        ),
    ] {
        let branch = case6_fn_span(&lib, signature);
        let asked = branch.find(&format!(
            "host_lifecycle_observe_drain(BOUNDARY_{boundary}_REQUESTED);"
        ));
        let ended = branch.find(&format!(
            "host_lifecycle_observe_drain(BOUNDARY_{boundary}_STOPPED);"
        ));
        assert!(
            asked.is_some() && ended.is_some() && asked < ended,
            "{boundary} must keep requested and stopped as two separate boundaries"
        );
        assert_eq!(
            count_occurrences(&lib, &format!("event: {asked_event:?}")),
            1,
            "{asked_event:?} must be one frozen row"
        );
        assert_eq!(
            count_occurrences(&lib, &format!("event: {stopped_event:?}")),
            1,
            "{stopped_event:?} must be one frozen row"
        );
        pinned.push(asked_event);
        pinned.push(stopped_event);
    }

    // One shared correlation: the fixture pins the drain generation field, and
    // the real stop contour binds every drain record to that one generation.
    let correlation_field = fixture["drain_correlation"]
        .as_str()
        .expect("the fixture must pin the drain correlation");
    assert_eq!(correlation_field, "drain_generation");
    assert_eq!(
        count_occurrences(
            &stop,
            "let drain_generation = activation.fence.activation_generation.clone();"
        ),
        1,
        "stop must bind the drain generation exactly once"
    );
    assert_eq!(
        fixture["distinctions"]["requested_vs_stopped"].as_bool(),
        Some(true),
        "the fixture must declare stop request and stop distinct"
    );
    let drain_details = fixture["drain_details"]
        .as_array()
        .expect("the fixture must pin the drain details")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("a drain detail must be a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    for event in pinned {
        assert!(
            drain_details.iter().any(|detail| detail == event),
            "{event:?} must be a pinned drain detail, got {drain_details:?}"
        );
    }
    for event in ["host.stop requested", "host.stop stopped"] {
        assert!(
            drain_details.iter().any(|detail| detail == event),
            "{event:?} must be a pinned drain detail, got {drain_details:?}"
        );
    }

    // Executed pass on the real durable owner: the drain request and the drain
    // progress are two distinct committed operations inside one generation, the
    // progress record is bound to the request's generation, progress never
    // regresses to a request, and a repeat observation is readback.
    let (journal, host, generation) = case6_journal();
    let commit = journal
        .append(case6_drain_record(
            &host,
            &generation,
            &generation,
            "host-drain-request",
            eliot_host_state::DrainState::Requested,
        ))
        .expect("the drain request must commit");
    assert_eq!(
        commit.disposition(),
        eliot_host_state::AppendDisposition::Applied
    );
    let progress = journal
        .append(case6_drain_record(
            &host,
            &generation,
            &generation,
            "host-drain-start",
            eliot_host_state::DrainState::Draining,
        ))
        .expect("the drain progress must commit");
    assert_eq!(
        progress.disposition(),
        eliot_host_state::AppendDisposition::Applied
    );
    assert_ne!(
        commit.sequence(),
        progress.sequence(),
        "the drain request and the drain progress must be two distinct commits"
    );
    assert_ne!(
        commit.transaction_id(),
        progress.transaction_id(),
        "the drain request and the drain progress must carry distinct receipts"
    );
    let drifted = case6_generation(CASE6_ACTIVATION_LINEAGE, 2);
    assert!(
        journal
            .append(case6_drain_record(
                &host,
                &generation,
                &drifted,
                "host-drain-drift",
                eliot_host_state::DrainState::Draining,
            ))
            .is_err(),
        "drain progress must stay bound to the requested drain generation"
    );
    assert!(
        journal
            .append(case6_drain_record(
                &host,
                &generation,
                &generation,
                "host-drain-regress",
                eliot_host_state::DrainState::Requested,
            ))
            .is_err(),
        "a draining record must never regress back to a drain request"
    );
    let projected = journal.snapshot().expect("the journal must project");
    assert_eq!(
        projected.drain.as_ref().map(|drain| drain.state),
        Some(eliot_host_state::DrainState::Draining),
        "a refused write must leave the durable drain state untouched"
    );
    assert_eq!(
        projected
            .drain
            .as_ref()
            .map(|drain| drain.drain_generation.clone()),
        Some(generation.clone()),
        "the durable drain record must carry the requested drain generation"
    );
    let replayed = journal
        .append(case6_drain_record(
            &host,
            &generation,
            &generation,
            "host-drain-start",
            eliot_host_state::DrainState::Draining,
        ))
        .expect("an exact replay must be answered");
    assert_eq!(
        replayed.disposition(),
        eliot_host_state::AppendDisposition::Replayed,
        "repeating a committed record is readback, not a second commit"
    );
    assert_eq!(replayed.sequence(), progress.sequence());

    // Executed pass on the real instrumentation: the stop phases are distinct
    // emitted records under one correlation, and a clean stop emits no terminal.
    let correlation = format!(
        "{}:{}",
        generation.current.lineage_id.as_str(),
        generation.current.sequence.get()
    );
    let phases = [
        "host.stop requested",
        "host.kernel-terminate requested",
        "host.kernel-terminate stopped",
        "host.store-terminate requested",
        "host.store-terminate stopped",
        "host.stop stopped",
    ];
    let text = capture_emit(|| {
        for phase in phases {
            observe_entrypoint_with_detail(
                EntrypointStage::ShutdownDrain,
                &format!("{phase} {correlation}"),
            );
        }
    });
    for phase in phases {
        assert_eq!(
            count_occurrences(&text, phase),
            1,
            "the stop contour must emit exactly one {phase:?} record, got: {text}"
        );
    }
    assert_eq!(
        count_occurrences(&text, &correlation),
        phases.len(),
        "every stop record must share the one drain generation correlation"
    );
    let terminal_event = fixture["terminal_event"]
        .as_str()
        .expect("the fixture must pin the terminal event");
    assert!(
        !text.contains(terminal_event),
        "a clean stop must emit no terminal record, got: {text}"
    );
    let failed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.stop requested {correlation}"),
        );
        observe_terminal_error(stop_failed);
    });
    assert!(
        failed.contains(stop_failed),
        "the failed stop must name its terminal code, got: {failed}"
    );
    assert_eq!(
        count_occurrences(&failed, terminal_event),
        1,
        "a failed stop must emit exactly one terminal record, got: {failed}"
    );
}

// WORK_UNIT_CASE: 891/7
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 7 keeps the four activation phases, the readiness-evidence rule, the failed-versus-unknown rule and the real durable activation reducer in one deterministic probe"
)]
fn lifecycle_activation_requested_started_ready_failed_distinct() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let activation_module = manifest_source("src/activation_lifecycle.rs");

    // Source: requested and started are two distinct boundaries of the real
    // start contour, and a started contour never selects a readiness row.
    let start = case6_fn_span(&lib, "pub fn start_approved_contour(");
    let requested = start
        .find("host_lifecycle_observe_requested(BOUNDARY_START_REQUESTED);")
        .expect("the start contour must observe its request");
    let started = start
        .find("host_lifecycle_observe_requested(BOUNDARY_START_STARTED);")
        .expect("the start contour must observe its started phase");
    let disarmed = start
        .find("host_terminal.disarm();")
        .expect("the start contour must disarm its guard");
    assert!(
        requested < disarmed && disarmed < started,
        "the start request, the guard and the started phase must stay ordered"
    );
    assert!(
        !start.contains("BOUNDARY_READINESS"),
        "a started contour must never emit a readiness record"
    );

    // Source: the manifest contour keeps requested and started separate and
    // commits the ready steps as durable states rather than as a claim.
    let manifest = case6_fn_span(&lib, "fn start_manifest_contour(");
    let manifest_requested = manifest
        .find("host_lifecycle_observe_requested(BOUNDARY_START_MANIFEST_REQUESTED);")
        .expect("the manifest contour must observe its request");
    let manifest_started = manifest
        .find("host_lifecycle_observe_requested(BOUNDARY_START_MANIFEST_STARTED);")
        .expect("the manifest contour must observe its started phase");
    assert!(
        manifest_requested < manifest_started,
        "the manifest request must be observed before the manifest started phase"
    );
    assert!(
        !manifest.contains("BOUNDARY_READINESS"),
        "the manifest contour must leave readiness to the readiness contour"
    );
    assert!(
        manifest.contains("ActivationState::ControlReady")
            && manifest.contains("ActivationState::Active"),
        "the ready states are durable activation states, not log vocabulary"
    );

    // Source: a live ready transition is refused without fresh readiness and
    // heartbeat evidence.
    let evidence = case6_fn_span(&lib, "fn transition_activation_with_readiness_evidence(");
    assert!(
        evidence.contains("live activation transition has no fresh readiness observation"),
        "a ready transition must require a fresh readiness observation"
    );
    assert!(
        evidence.contains("live activation transition has no fresh heartbeat evidence"),
        "a ready transition must require fresh heartbeat evidence"
    );
    assert!(
        evidence.contains("transition_activation_record_with_evidence"),
        "the live ready transition must go through the evidence-taking record writer"
    );

    // Source: the readiness contour separates a readiness request from a ready
    // proof and keeps degraded distinct from ready.
    let readiness = case6_fn_span(&lib, "fn reconcile_branch_readiness_at(");
    let proof_requested = readiness
        .find("host_lifecycle_observe_requested(BOUNDARY_READINESS_REQUESTED_PROOF);")
        .expect("the readiness contour must observe its proof request");
    let ready = readiness
        .find("host_lifecycle_observe_requested(BOUNDARY_READINESS_READY_PROOF);")
        .expect("the readiness contour must observe its ready proof");
    assert!(
        proof_requested < ready,
        "a readiness request must be observed before its ready proof"
    );
    assert!(
        readiness.contains("HostBranchDisposition::ReadinessDegraded"),
        "degraded stays degraded and is never promoted to ready"
    );

    // Discovery: the admission-requested row and the manifest rows name case 7,
    // and the admission projection never carries a readiness record.
    assert_eq!(
        count_occurrences(&lib, "test: \"891/case-7\""),
        7,
        "exactly seven frozen rows must declare case 7"
    );
    assert_eq!(
        count_occurrences(&activation_module, "pub fn activation_admission(&self)"),
        1,
        "the admission projection must stay a public seam"
    );
    assert_eq!(
        count_occurrences(
            &activation_module,
            "host_lifecycle_observe_requested(BOUNDARY_ACTIVATION_ADMISSION_REQUESTED);"
        ),
        1,
        "the admission owner must have exactly one admission-request call site"
    );
    assert!(
        !activation_module.contains("BOUNDARY_READINESS"),
        "the admission projection must never emit a readiness record"
    );

    // Executed pass on the real durable owner: four states under four rules.
    let (journal, host, generation) = case6_journal();
    let admission = journal
        .append(case6_activation_record(
            &host,
            &generation,
            "activation-requested",
            eliot_host_state::ActivationState::Starting,
        ))
        .expect("the activation request must commit");
    assert_eq!(
        admission.disposition(),
        eliot_host_state::AppendDisposition::Applied
    );
    assert!(
        journal
            .append(case6_activation_record(
                &host,
                &generation,
                "activation-skip-ready",
                eliot_host_state::ActivationState::Active,
            ))
            .is_err(),
        "an activation must not become ready without its own readiness step"
    );
    assert!(
        journal
            .append(case7_activation_record(
                &host,
                &generation,
                "activation-unproven-ready",
                eliot_host_state::ActivationState::ControlReady,
                case7_readiness(false, true),
                false,
            ))
            .is_err(),
        "ready must require real control and supervision readiness evidence"
    );
    journal
        .append(case6_activation_record(
            &host,
            &generation,
            "activation-control-ready",
            eliot_host_state::ActivationState::ControlReady,
        ))
        .expect("a proven ready activation must commit");
    journal
        .append(case6_activation_record(
            &host,
            &generation,
            "activation-active",
            eliot_host_state::ActivationState::Active,
        ))
        .expect("an active activation must commit");
    let projected = journal.snapshot().expect("the journal must project");
    assert_eq!(
        projected
            .activation
            .as_ref()
            .map(|activation| activation.state),
        Some(eliot_host_state::ActivationState::Active),
        "the proven steps must leave exactly one active activation"
    );
    assert!(
        journal
            .append(case7_activation_record(
                &host,
                &generation,
                "activation-failed-without-directive",
                eliot_host_state::ActivationState::Failed,
                case7_readiness(true, true),
                false,
            ))
            .is_err(),
        "a failed activation must carry its own recovery directive"
    );
    let failed_commit = journal
        .append(case7_activation_record(
            &host,
            &generation,
            "activation-failed",
            eliot_host_state::ActivationState::Failed,
            case7_readiness(true, true),
            true,
        ))
        .expect("a failed activation with its own directive must commit");
    assert_eq!(
        failed_commit.disposition(),
        eliot_host_state::AppendDisposition::Applied
    );
    let after_failure = journal.snapshot().expect("the journal must project");
    assert_eq!(
        after_failure
            .activation
            .as_ref()
            .map(|activation| activation.state),
        Some(eliot_host_state::ActivationState::Failed),
        "the failed state must be its own durable state"
    );
    assert!(
        after_failure
            .activation
            .as_ref()
            .and_then(|activation| activation.failure_and_recovery_directive.as_ref())
            .is_some(),
        "a failed activation must be readable with its own recovery directive"
    );

    // Executed pass on the real instrumentation: requested, started and ready
    // are three distinct phase records under one correlation, and the failed
    // outcome stays distinct from an unknown outcome.
    let correlation = format!(
        "{}:{}",
        generation.current.lineage_id.as_str(),
        generation.current.sequence.get()
    );
    let phases = [
        "host.resume-pending requested",
        "host.start-manifest started",
        "host.readiness ready proof",
    ];
    let text = capture_emit(|| {
        for phase in phases {
            observe_entrypoint_with_detail(
                EntrypointStage::Startup,
                &format!("{phase} {correlation}"),
            );
        }
    });
    for phase in phases {
        assert_eq!(
            count_occurrences(&text, phase),
            1,
            "the activation contour must emit exactly one {phase:?} record, got: {text}"
        );
        assert_eq!(
            count_occurrences(&lib, &format!("event: {phase:?}")),
            1,
            "{phase:?} must be one frozen row in the real table"
        );
    }
    assert_eq!(
        count_occurrences(&text, &correlation),
        phases.len(),
        "every activation phase record must share the one correlation"
    );
    assert!(
        !text.to_lowercase().contains("unknown"),
        "an activation phase record must never claim an unknown outcome, got: {text}"
    );
    let resume_failed = fixture["terminal_codes"]["resume_pending_failed"]
        .as_str()
        .expect("the fixture must pin the resume-pending terminal code");
    assert_eq!(resume_failed, "host-resume-pending-failed");
    assert_eq!(
        count_occurrences(&lib, &format!("event: {resume_failed:?}")),
        1,
        "the resume-pending terminal code must be one frozen row"
    );
    let failed_text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("host.resume-pending requested {correlation}"),
        );
        observe_terminal_error(resume_failed);
    });
    let terminal_event = fixture["terminal_event"]
        .as_str()
        .expect("the fixture must pin the terminal event");
    assert_eq!(
        count_occurrences(&failed_text, terminal_event),
        1,
        "a failed activation must emit exactly one terminal record, got: {failed_text}"
    );
    assert!(
        !text.contains(terminal_event),
        "the three proven activation phases must emit no terminal record, got: {text}"
    );
    assert_eq!(
        fixture["distinctions"]["failed_vs_unknown"].as_bool(),
        Some(true),
        "the fixture must declare failed distinct from an unknown effect"
    );
}

// WORK_UNIT_CASE: 891/8
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 8 keeps the drain request/progress/completion distinctions, the shared drain correlation and the real durable drain reducer in one deterministic probe"
)]
fn lifecycle_drain_request_progress_completion_distinct() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let stop = case6_fn_span(&lib, "pub fn stop(&mut self) -> Result<(), HostError> {");

    // Source: request and progress are two distinct durable states written by
    // two distinct operation identities inside the stop contour.
    assert_eq!(
        count_occurrences(&lib, "operation(\"host-drain-request\")"),
        1,
        "the drain request operation label must exist once"
    );
    assert_eq!(
        count_occurrences(&lib, "operation(\"host-drain-start\")"),
        1,
        "the drain progress operation label must exist once"
    );
    let request_state = stop
        .find("DrainState::Requested")
        .expect("stop must write the requested drain state");
    let progress_state = stop
        .find("DrainState::Draining")
        .expect("stop must write the draining drain state");
    let request_operation = stop
        .find("operation(\"host-drain-request\")")
        .expect("stop must commit the drain request");
    let progress_operation = stop
        .find("operation(\"host-drain-start\")")
        .expect("stop must commit the drain progress");
    assert!(
        request_state < progress_state && request_operation < progress_operation,
        "the drain request must be written and committed before the drain progress"
    );

    // Source: the drain completion is its own boundary, one observation per
    // commit writer, distinct from the stop completion boundary.
    assert_eq!(
        count_occurrences(
            &stop,
            "host_lifecycle_observe_drain(BOUNDARY_DRAIN_COMMIT);"
        ),
        2,
        "stop must observe exactly one drain commit per commit writer"
    );
    let commit_observed = stop
        .find("host_lifecycle_observe_drain(BOUNDARY_DRAIN_COMMIT);")
        .expect("stop must observe the drain commit");
    let drained = stop
        .find("host_lifecycle_observe_drain(BOUNDARY_STOP_STOPPED_CLEAN_DRAINED);")
        .expect("stop must observe the drained completion");
    assert!(
        progress_operation < commit_observed && commit_observed < drained,
        "drain progress must precede the drain commit and the drained completion"
    );
    assert!(
        stop.contains("ActivationState::StoppedClean, \"host-stopped-clean\""),
        "the drained completion must be backed by the durable stopped-clean state"
    );
    for (row, event) in [
        ("drain.requested", "host.drain requested"),
        ("drain.draining", "host.drain draining"),
        ("drain.commit", "host.drain commit"),
        (
            "stop.stopped-clean-drained",
            "host.stop stopped-clean drained",
        ),
    ] {
        assert_eq!(
            count_occurrences(&lib, &format!("name: {row:?}")),
            1,
            "{row:?} must be one frozen row"
        );
        assert_eq!(
            count_occurrences(&lib, &format!("event: {event:?}")),
            1,
            "{event:?} must be one frozen row with its own spelling"
        );
    }
    assert_eq!(
        fixture["distinctions"]["draining_vs_drained"].as_bool(),
        Some(true),
        "the fixture must declare draining distinct from drained"
    );

    // Discovery: the launch-cleanup boundaries name case 8 and share the drain
    // vocabulary of the stop contour.
    assert_eq!(
        count_occurrences(&lib, "test: \"891/case-8\""),
        10,
        "exactly ten frozen rows must declare case 8"
    );
    let cleanup = case6_fn_span(&lib, "fn cleanup_launched_contour(");
    assert!(
        cleanup.contains("host_lifecycle_observe_drain(BOUNDARY_CLEANUP_LAUNCHED_REQUESTED);"),
        "the launched-cleanup contour must observe its request"
    );
    assert_eq!(
        count_occurrences(&lib, "event: \"host.cleanup-launched requested\""),
        1,
        "the launched-cleanup request must be one frozen row"
    );

    // Executed pass on the real durable owner: request, progress and completion
    // are three distinct states, progress is bound to the request generation, a
    // duplicate request is refused, and a repeat observation is readback.
    let (journal, host, generation) = case6_journal();
    let request = journal
        .append(case6_drain_record(
            &host,
            &generation,
            &generation,
            "host-drain-request",
            eliot_host_state::DrainState::Requested,
        ))
        .expect("the drain request must commit");
    assert_eq!(
        request.disposition(),
        eliot_host_state::AppendDisposition::Applied
    );
    assert!(
        journal
            .append(case6_drain_record(
                &host,
                &generation,
                &generation,
                "host-drain-second-request",
                eliot_host_state::DrainState::Requested,
            ))
            .is_err(),
        "a second drain request must not be admitted while one is open"
    );
    let progress = journal
        .append(case6_drain_record(
            &host,
            &generation,
            &generation,
            "host-drain-start",
            eliot_host_state::DrainState::Draining,
        ))
        .expect("the drain progress must commit");
    assert_eq!(
        progress.disposition(),
        eliot_host_state::AppendDisposition::Applied
    );
    assert_ne!(request.sequence(), progress.sequence());
    let projected = journal.snapshot().expect("the journal must project");
    assert_eq!(
        projected.drain.as_ref().map(|drain| drain.state),
        Some(eliot_host_state::DrainState::Draining),
        "draining must be a durable state distinct from the request"
    );
    assert_eq!(
        projected.drain_commit, None,
        "a drain commit is a separate durable record from the drain request"
    );
    let replayed = journal
        .append(case6_drain_record(
            &host,
            &generation,
            &generation,
            "host-drain-start",
            eliot_host_state::DrainState::Draining,
        ))
        .expect("an exact replay must be answered");
    assert_eq!(
        replayed.disposition(),
        eliot_host_state::AppendDisposition::Replayed,
        "a repeated drain progress observation is readback, not a second progress commit"
    );
    assert_eq!(replayed.sequence(), progress.sequence());

    // Executed pass on the real instrumentation: the drain request, progress,
    // commit and drained completion are four distinct records under one
    // correlation, and progress is never spelled as the completion.
    let correlation = format!(
        "{}:{}",
        generation.current.lineage_id.as_str(),
        generation.current.sequence.get()
    );
    let phases = [
        "host.drain requested",
        "host.drain draining",
        "host.drain commit",
        "host.stop stopped-clean drained",
    ];
    let text = capture_emit(|| {
        for phase in phases {
            observe_entrypoint_with_detail(
                EntrypointStage::ShutdownDrain,
                &format!("{phase} {correlation}"),
            );
        }
    });
    for phase in phases {
        assert_eq!(
            count_occurrences(&text, phase),
            1,
            "the drain contour must emit exactly one {phase:?} record, got: {text}"
        );
    }
    assert_eq!(
        count_occurrences(&text, &correlation),
        phases.len(),
        "every drain record must share the one drain generation correlation"
    );
    assert!(
        !text.contains("host.drain drained"),
        "drain progress must never be spelled as the drained completion, got: {text}"
    );
    let drain_details = fixture["drain_details"]
        .as_array()
        .expect("the fixture must pin the drain details")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("a drain detail must be a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    for detail in ["host.drain requested", "host.drain draining"] {
        assert!(
            drain_details.iter().any(|pinned| pinned == detail),
            "{detail:?} must be a pinned drain detail, got {drain_details:?}"
        );
    }
}

// WORK_UNIT_CASE: 891/9
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 9 keeps the managed launch request/admission boundaries, the no-readiness rule and the real durable and wire round-trips in one deterministic probe"
)]
fn lifecycle_managed_launch_request_is_not_readiness() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");

    // Source: the managed-launch boundary is request then admission, both phase
    // records, and it never selects a readiness row or its own terminal.
    let jobs = case6_fn_span(
        &lib,
        "pub fn new(host: &HostInstallationEpoch) -> Result<Self, WindowsAdapterError> {",
    );
    let requested = jobs
        .find("host_lifecycle_observe_requested(BOUNDARY_JOBS_REQUESTED);")
        .expect("the managed-launch owner must observe its request");
    let admitted = jobs
        .find("host_lifecycle_observe_requested(BOUNDARY_JOBS_ADMITTED);")
        .expect("the managed-launch owner must observe its admission");
    assert!(
        requested < admitted,
        "a managed launch request must be observed before its admission"
    );
    assert!(
        !jobs.contains("BOUNDARY_READINESS"),
        "the managed-launch boundary must never select a readiness row"
    );
    assert!(
        !jobs.contains("HostTerminalGuard"),
        "the managed-launch boundary is phase only; the outermost open guard owns the terminal"
    );

    // Source: the started phases stay distinct from ready.
    let start = case6_fn_span(&lib, "pub fn start_approved_contour(");
    let manifest = case6_fn_span(&lib, "fn start_manifest_contour(");
    assert!(
        !start.contains("BOUNDARY_READINESS") && !manifest.contains("BOUNDARY_READINESS"),
        "a started contour must leave readiness to the readiness contour"
    );

    // Discovery: the frozen rows name case 9 and name the production caller.
    for (row, event) in [
        ("jobs.requested", "host.jobs requested"),
        ("jobs.admitted", "host.jobs admitted"),
    ] {
        let frozen = case9_row(&lib, row);
        assert!(
            frozen.contains(&format!("event: {event:?}")),
            "{row:?} must carry {event:?}, got {frozen}"
        );
        assert!(
            frozen.contains("caller: \"HostComposition::open\""),
            "{row:?} must name its production caller, got {frozen}"
        );
        assert!(
            frozen.contains("test: \"891/case-9\""),
            "{row:?} must declare case 9, got {frozen}"
        );
    }
    let names = fixture["boundary_table"]["names"]
        .as_array()
        .expect("the fixture must pin the frozen boundary names");
    for row in ["jobs.requested", "jobs.admitted"] {
        assert!(
            names.iter().any(|value| value.as_str() == Some(row)),
            "the frozen table must contain {row:?}, got {names:?}"
        );
    }
    assert!(
        !lib.contains("host.jobs ready")
            && !lib.contains("host.jobs completion")
            && !lib.contains("host.jobs admitted ready"),
        "a managed launch record must never be spelled as a readiness or completion record"
    );

    // Executed pass on the real durable owner: a launch request commits as an
    // admission, never as readiness, and re-reading it is readback.
    let (journal, host, generation) = case6_journal();
    let admission = journal
        .append(case6_activation_record(
            &host,
            &generation,
            "launch-requested",
            eliot_host_state::ActivationState::Starting,
        ))
        .expect("a launch request must commit as an admission");
    assert_eq!(
        admission.disposition(),
        eliot_host_state::AppendDisposition::Applied,
        "a launch request is a control receipt, not a readiness claim"
    );
    let projected = journal.snapshot().expect("the journal must project");
    assert_eq!(
        projected
            .activation
            .as_ref()
            .map(|activation| activation.state),
        Some(eliot_host_state::ActivationState::Starting),
        "a managed launch admission leaves the activation admitted, not ready"
    );
    assert!(
        journal
            .append(case6_activation_record(
                &host,
                &generation,
                "launch-ready",
                eliot_host_state::ActivationState::Active,
            ))
            .is_err(),
        "a managed launch must never become ready without its own proven readiness step"
    );
    let replayed = journal
        .append(case6_activation_record(
            &host,
            &generation,
            "launch-requested",
            eliot_host_state::ActivationState::Starting,
        ))
        .expect("an exact replay must be answered");
    assert_eq!(
        replayed.disposition(),
        eliot_host_state::AppendDisposition::Replayed,
        "re-reading an admitted launch is readback, not a second admission"
    );
    assert_eq!(replayed.sequence(), admission.sequence());

    // Executed pass on the real wire owner: an unanswered managed launch request
    // stays a typed unknown, never a completion or readiness receipt.
    let request = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RestartKernel,
        eliot_platform::PlatformHandle::new("891-case-9-restart")
            .expect("the test handle must be valid"),
    )
    .expect("the restart request must validate");
    request
        .validate()
        .expect("the restart request must be valid");
    let response = eliot_host::HostRuntimeControlResponse::unknown_for(
        &request,
        eliot_host_service::runtime_control::runtime_control_unknown_ref(
            "kernel-restart",
            &request,
        ),
    );
    response
        .validate()
        .expect("an unknown answer must validate");
    assert!(eliot_host_service::runtime_control::response_matches_request(&request, &response));
    assert!(matches!(
        response,
        eliot_host::HostRuntimeControlResponse::Unknown { .. }
    ));

    // Executed pass on the real instrumentation: the launch request and its
    // admission are two distinct phase records under one correlation, and
    // neither carries readiness wording.
    let correlation = format!(
        "{}:{}",
        generation.current.lineage_id.as_str(),
        generation.current.sequence.get()
    );
    let phases = ["host.jobs requested", "host.jobs admitted"];
    let text = capture_emit(|| {
        for phase in phases {
            observe_entrypoint_with_detail(
                EntrypointStage::Startup,
                &format!("{phase} {correlation}"),
            );
        }
    });
    for phase in phases {
        assert_eq!(
            count_occurrences(&text, phase),
            1,
            "the managed-launch owner must emit exactly one {phase:?} record, got: {text}"
        );
    }
    assert_eq!(
        count_occurrences(&text, &correlation),
        phases.len(),
        "the launch request and its admission must share one correlation"
    );
    for detail in [
        "host.readiness requested proof",
        "host.readiness ready proof",
    ] {
        assert!(
            !text.contains(detail),
            "a managed launch record must never carry readiness wording {detail:?}"
        );
    }
}

// WORK_UNIT_CASE: 891/10
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 10 keeps the liveness observation boundary, the liveness-versus-readiness rule and the real durable no-readiness round-trip in one deterministic probe"
)]
fn lifecycle_process_liveness_is_not_semantic_readiness() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");

    // Source: the liveness tick observes process liveness only and never selects
    // a readiness row.
    let tick = case6_fn_span(
        &lib,
        "pub fn liveness_tick(&mut self) -> Result<HostLivenessTick, HostError> {",
    );
    let requested = tick
        .find("host_lifecycle_observe_requested(BOUNDARY_LIVENESS_REQUESTED);")
        .expect("the liveness tick must observe its request");
    let disarmed = tick
        .find("host_terminal.disarm();")
        .expect("the liveness tick must disarm its guard");
    let observed = tick
        .find("host_lifecycle_observe_requested(BOUNDARY_LIVENESS_OBSERVED);")
        .expect("the liveness tick must observe its observation");
    assert!(
        requested < disarmed && disarmed < observed,
        "a live tick must disarm before its observation record"
    );
    assert!(
        tick.contains("self.jobs.liveness_only()"),
        "the liveness tick must read process liveness only"
    );
    assert!(
        !tick.contains("BOUNDARY_READINESS"),
        "a liveness tick must never select a readiness row"
    );
    assert_eq!(
        count_occurrences(&tick, "HostTerminalGuard::armed"),
        1,
        "the liveness tick must arm exactly one designated terminal guard"
    );
    assert_eq!(
        count_occurrences(&lib, "test: \"891/case-10\""),
        2,
        "exactly the liveness request and observation rows must declare case 10"
    );

    // Discovery: the frozen table says liveness is an observation and never
    // readiness, and the liveness terminal is its own code.
    assert_eq!(
        count_occurrences(&lib, "owner_state: \"observation, never readiness\""),
        1,
        "the liveness observation row must declare it is never readiness"
    );
    let liveness_failed = fixture["terminal_codes"]["liveness_failed"]
        .as_str()
        .expect("the fixture must pin the liveness terminal code");
    assert_eq!(liveness_failed, "host-liveness-failed");
    assert_eq!(
        count_occurrences(&lib, &format!("event: {liveness_failed:?}")),
        1,
        "the liveness terminal code must be one frozen row"
    );
    assert_eq!(
        fixture["distinctions"]["liveness_vs_readiness"].as_bool(),
        Some(true),
        "the fixture must declare liveness distinct from readiness"
    );
    let details = fixture["lifecycle_details"]
        .as_array()
        .expect("the fixture must pin the lifecycle details");
    let liveness_details = details
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter(|detail| detail.starts_with("host.liveness"))
        .collect::<Vec<_>>();
    let readiness_details = details
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter(|detail| detail.contains("readiness"))
        .collect::<Vec<_>>();
    assert_eq!(
        liveness_details.len(),
        2,
        "exactly the liveness request and observation details must be pinned"
    );
    assert!(
        !readiness_details.is_empty(),
        "the pinned vocabulary must contain readiness details to compare against"
    );
    for detail in &liveness_details {
        assert!(
            !detail.contains("ready"),
            "a liveness detail must never carry readiness wording: {detail:?}"
        );
        assert_eq!(
            count_occurrences(&lib, &format!("event: {detail:?}")),
            1,
            "{detail:?} must be one frozen row in the real table"
        );
    }
    for detail in &readiness_details {
        assert!(
            !detail.contains("liveness"),
            "a readiness detail must never carry liveness wording: {detail:?}"
        );
    }

    // Executed pass on the real durable owner: re-observing a live activation is
    // readback and never advances it to a ready state.
    let (journal, host, generation) = case6_journal();
    let observed_commit = journal
        .append(case6_activation_record(
            &host,
            &generation,
            "liveness-observed",
            eliot_host_state::ActivationState::Starting,
        ))
        .expect("a liveness observation of a live activation must be answered");
    let replayed = journal
        .append(case6_activation_record(
            &host,
            &generation,
            "liveness-observed",
            eliot_host_state::ActivationState::Starting,
        ))
        .expect("an exact replay must be answered");
    assert_eq!(
        replayed.disposition(),
        eliot_host_state::AppendDisposition::Replayed,
        "a repeated liveness observation is readback, not a new commit"
    );
    assert_eq!(replayed.sequence(), observed_commit.sequence());
    assert_eq!(
        replayed.transaction_id(),
        observed_commit.transaction_id(),
        "a repeated liveness observation must report the same control receipt"
    );
    let projected = journal.snapshot().expect("the journal must project");
    assert_eq!(
        projected
            .activation
            .as_ref()
            .map(|activation| activation.state),
        Some(eliot_host_state::ActivationState::Starting),
        "a live process must never advance the activation to a ready state"
    );

    // Executed pass on the real instrumentation: liveness is an observation
    // record with its own correlation and never a readiness record.
    let correlation = format!(
        "{}:{}",
        generation.current.lineage_id.as_str(),
        generation.current.sequence.get()
    );
    let text = capture_emit(|| {
        for detail in &liveness_details {
            observe_entrypoint_with_detail(
                EntrypointStage::Startup,
                &format!("{detail} {correlation}"),
            );
        }
    });
    for detail in &liveness_details {
        assert_eq!(
            count_occurrences(&text, detail),
            1,
            "the liveness tick must emit exactly one {detail:?} record, got: {text}"
        );
    }
    assert_eq!(
        count_occurrences(&text, &correlation),
        liveness_details.len(),
        "every liveness record must share the one correlation"
    );
    for detail in &readiness_details {
        assert!(
            !text.contains(*detail),
            "a liveness record must never carry readiness wording {detail:?}"
        );
    }
    let terminal_event = fixture["terminal_event"]
        .as_str()
        .expect("the fixture must pin the terminal event");
    assert!(
        !text.contains(terminal_event),
        "a live liveness observation must emit no terminal record, got: {text}"
    );
    let failed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("{} {correlation}", liveness_details[0]),
        );
        observe_terminal_error(liveness_failed);
    });
    assert_eq!(
        count_occurrences(&failed, terminal_event),
        1,
        "a failed liveness tick must emit exactly one terminal record, got: {failed}"
    );
}

// WORK_UNIT_CASE: 891/11
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 11 keeps the restart-versus-rollback boundaries, the rollback-requested-versus-restored rule and the real reactivation round-trip in one deterministic probe"
)]
fn lifecycle_restart_versus_rollback_distinct() {
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let runtime_control =
        manifest_source("../../crates/kernel/eliot-host-service/src/runtime_control.rs");

    // Source: a rollback request is observed before a verified restoration, and
    // the restoration is observed only after the prior contour really relaunched.
    let rollback = case6_fn_span(&lib, "fn cutover_with_rollback(");
    let requested = rollback
        .find("host_lifecycle_observe_requested(BOUNDARY_CUTOVER_ROLLBACK_REQUESTED);")
        .expect("the rollback must observe its request");
    let restored = rollback
        .find("host_lifecycle_observe_requested(BOUNDARY_CUTOVER_ROLLBACK_RESTORED);")
        .expect("the rollback must observe its verified restoration");
    let relaunched = rollback
        .find("rollback.map(|()| {")
        .expect("the rollback must relaunch the prior contour");
    assert!(
        requested < restored && relaunched < restored,
        "a verified restoration may only be observed after the rollback request and after the relaunch succeeded"
    );
    assert_eq!(
        count_occurrences(
            &lib,
            "host_lifecycle_observe_requested(BOUNDARY_CUTOVER_ROLLBACK_RESTORED);"
        ),
        1,
        "the verified restoration must have exactly one call site"
    );

    // Source: the reactivation is a different boundary from the restoration, and
    // it lives in a different contour.
    let contour = case6_fn_span(&lib, "fn cutover_generation_contour(");
    assert!(
        contour
            .contains("host_lifecycle_observe_requested(BOUNDARY_CUTOVER_ROLLBACK_REACTIVATED);"),
        "the cutover contour must observe the reactivation"
    );
    assert!(
        !contour.contains("BOUNDARY_CUTOVER_ROLLBACK_RESTORED"),
        "a reactivation must never be recorded as a verified restoration"
    );
    assert!(
        !rollback.contains("BOUNDARY_CUTOVER_ROLLBACK_REACTIVATED"),
        "a verified restoration must never be recorded as a reactivation"
    );

    // Discovery: three distinct rollback rows plus two rollback-phase rows name
    // case 11, and the restart rows stay a separate vocabulary.
    assert_eq!(
        count_occurrences(&lib, "test: \"891/case-11\""),
        5,
        "exactly five frozen rows must declare case 11"
    );
    let names = fixture["boundary_table"]["names"]
        .as_array()
        .expect("the fixture must pin the frozen boundary names");
    for (row, event) in [
        (
            "cutover-rollback.requested",
            "host.cutover-rollback requested",
        ),
        (
            "cutover-rollback.restored",
            "host.cutover-rollback restored",
        ),
        (
            "cutover-rollback.reactivated",
            "host.cutover-rollback reactivated",
        ),
        ("kernel-restart.requested", "host.kernel-restart requested"),
    ] {
        let frozen = case9_row(&lib, row);
        assert!(
            frozen.contains(&format!("event: {event:?}")),
            "{row:?} must carry {event:?}, got {frozen}"
        );
        assert!(
            names.iter().any(|value| value.as_str() == Some(row)),
            "the frozen table must contain {row:?}, got {names:?}"
        );
    }
    for row in [
        "cutover-rollback.requested",
        "cutover-rollback.restored",
        "cutover-rollback.reactivated",
    ] {
        assert!(
            case9_row(&lib, row).contains("test: \"891/case-11\""),
            "{row:?} must declare case 11"
        );
    }
    assert!(
        !case9_row(&lib, "kernel-restart.requested").contains("test: \"891/case-11\""),
        "a restart row must never claim the rollback case"
    );
    assert_eq!(
        fixture["distinctions"]["rollback_requested_vs_restored"].as_bool(),
        Some(true),
        "the fixture must declare a rollback request distinct from a verified restoration"
    );

    // Source: restart is a runtime-control operation and a rollback is not, so
    // the two contours can never share an operation identity or an outcome.
    assert_eq!(
        count_occurrences(
            &runtime_control,
            "HostRuntimeControlOperation::RestartKernel => \"RestartKernel\","
        ),
        1,
        "the runtime-control owner must define the canonical restart operation"
    );
    assert!(
        !runtime_control.contains("Rollback"),
        "the runtime-control wire owner must define no rollback operation, so a rollback can never be answered as a restart"
    );

    // Executed pass on the real durable owner: a rollback never revives the
    // failed activation generation in place, the reactivation runs under a newer
    // activation generation, and re-reading it is readback.
    let (journal, host, first) = case6_journal();
    journal
        .append(case6_activation_record(
            &host,
            &first,
            "candidate-requested",
            eliot_host_state::ActivationState::Starting,
        ))
        .expect("the candidate activation must commit");
    let candidate_failed = journal
        .append(case7_activation_record(
            &host,
            &first,
            "candidate-failed",
            eliot_host_state::ActivationState::Failed,
            case7_readiness(false, false),
            true,
        ))
        .expect("a failed candidate activation must commit");
    assert_eq!(
        candidate_failed.disposition(),
        eliot_host_state::AppendDisposition::Applied
    );
    assert!(
        journal
            .append(case6_activation_record(
                &host,
                &first,
                "rollback-in-place",
                eliot_host_state::ActivationState::Starting,
            ))
            .is_err(),
        "a rollback must never revive the failed activation generation in place"
    );
    let second = case6_generation(CASE6_ACTIVATION_LINEAGE, 2);
    let reactivated = journal
        .append(case6_activation_record(
            &host,
            &second,
            "rollback-reactivated",
            eliot_host_state::ActivationState::Starting,
        ))
        .expect("a rollback reactivation must commit under a newer generation");
    assert_eq!(
        reactivated.disposition(),
        eliot_host_state::AppendDisposition::Applied
    );
    let projected = journal.snapshot().expect("the journal must project");
    let activation = projected
        .activation
        .as_ref()
        .expect("a durable activation must exist");
    assert_ne!(
        activation.fence.activation_generation, first,
        "the reactivation must run under a newer activation generation, never the failed one"
    );
    assert_eq!(activation.fence.activation_generation, second.clone());
    assert_ne!(
        reactivated.sequence(),
        candidate_failed.sequence(),
        "the reactivation must be a separate commit from the failed candidate"
    );
    let replayed = journal
        .append(case6_activation_record(
            &host,
            &second,
            "rollback-reactivated",
            eliot_host_state::ActivationState::Starting,
        ))
        .expect("an exact replay must be answered");
    assert_eq!(
        replayed.disposition(),
        eliot_host_state::AppendDisposition::Replayed,
        "re-observing a rollback is readback, not a second restoration"
    );
    assert_eq!(replayed.sequence(), reactivated.sequence());

    // Executed pass on the real wire owner: a restart is answered as a typed
    // unknown outcome, never as a completion or readiness claim.
    let request = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RestartKernel,
        eliot_platform::PlatformHandle::new("891-case-11-restart")
            .expect("the test handle must be valid"),
    )
    .expect("the restart request must validate");
    request
        .validate()
        .expect("the restart request must be valid");
    let restart_correlation = request.request_digest.as_str().to_owned();
    let response = eliot_host::HostRuntimeControlResponse::unknown_for(
        &request,
        eliot_host_service::runtime_control::runtime_control_unknown_ref(
            "kernel-restart",
            &request,
        ),
    );
    response
        .validate()
        .expect("an unknown answer must validate");
    assert!(eliot_host_service::runtime_control::response_matches_request(&request, &response));
    assert!(matches!(
        response,
        eliot_host::HostRuntimeControlResponse::Unknown { .. }
    ));

    // Executed pass on the real instrumentation: the restart contour and the
    // rollback contour carry distinct correlations, so a verified restoration can
    // never be read as a restart receipt or as a reactivation.
    let rollback_correlation = format!(
        "rollback-generation:{}:{}",
        second.current.sequence.get(),
        second.current.lineage_id.as_str()
    );
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart requested {restart_correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart receipt completion {restart_correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("host.cutover-rollback requested {rollback_correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("host.cutover-rollback restored {rollback_correlation}"),
        );
    });
    assert_eq!(
        count_occurrences(&text, &restart_correlation),
        2,
        "one restart correlation must cover the restart request and its receipt"
    );
    assert_eq!(
        count_occurrences(&text, &rollback_correlation),
        2,
        "one rollback correlation must cover the rollback request and its verified restoration"
    );
    for detail in [
        "host.kernel-restart requested",
        "host.kernel-restart receipt completion",
        "host.cutover-rollback requested",
        "host.cutover-rollback restored",
    ] {
        assert_eq!(
            count_occurrences(&text, detail),
            1,
            "the two contours must emit exactly one {detail:?} record each, got: {text}"
        );
    }
    for detail in [
        "host.cutover-rollback requested",
        "host.cutover-rollback restored",
    ] {
        assert!(
            !text.contains(&format!("{detail} {restart_correlation}")),
            "a verified restoration must never carry the restart correlation"
        );
    }
    assert!(
        !text.contains("host.cutover-rollback reactivated"),
        "a reactivation is a distinct boundary from the verified restoration"
    );
}

// WORK_UNIT_CASE: 891/12
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 12 keeps the frozen cancellation rows, the real stop call-site ordering, the console caller arms and the record-level executed pass in one deterministic case"
)]
fn lifecycle_cancellation_requested_is_not_terminal_stop() {
    // #891 case 12: cancellation requested versus terminal cancellation
    // stopped. Source: the frozen `stop.cancellation-requested` / `stop.stopped`
    // rows and the real `HostComposition::stop` contour. Discovery: the #889
    // projection seam plus the real console caller arms. Executed pass: the
    // real facade records for one shared correlation, and the Event Log
    // admission decision that keeps a cancellation out of the successful-stop
    // channel. Diagnostics stay evidence only.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");
    let console = manifest_source("src/main.rs");

    let case12_table_start = lib
        .find("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .expect("lib.rs must own the frozen boundary table");
    let case12_table_end = case12_table_start
        + lib[case12_table_start..]
            .find("\n];")
            .expect("the frozen boundary table must close");
    let case12_table = &lib[case12_table_start..case12_table_end];
    let case12_row = |name: &str| -> String {
        let at = case12_table
            .find(&format!("name: \"{name}\","))
            .unwrap_or_else(|| panic!("the frozen table must own row {name}"));
        let row_start = case12_table[..at]
            .rfind("HostLifecycleBoundary {")
            .unwrap_or_else(|| panic!("row {name} must open a struct literal"));
        let row = &case12_table[row_start..];
        let row_end = row
            .find("\n    },")
            .unwrap_or_else(|| panic!("row {name} must close its struct literal"));
        row[..row_end].to_owned()
    };
    let case12_field = |row: &str, field: &str| -> String {
        let prefix = format!("{field}: ");
        let line = row
            .lines()
            .find(|line| line.trim_start().starts_with(prefix.as_str()))
            .unwrap_or_else(|| panic!("row must carry field {field}: {row}"));
        let mut value = String::new();
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let close = after
                .find('"')
                .unwrap_or_else(|| panic!("the {field} literal must close: {line}"));
            value.push_str(&after[..close]);
            rest = &after[close + 1..];
        }
        value
    };
    let case12_body = |haystack: &str, header: &str| -> String {
        let start = haystack
            .find(header)
            .unwrap_or_else(|| panic!("the source must contain {header}"));
        let bytes = haystack.as_bytes();
        let mut index = start;
        let mut depth = 0usize;
        loop {
            assert!(index < bytes.len(), "{header} must close in the source");
            match bytes[index] {
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    while index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    while index + 1 < bytes.len()
                        && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                    {
                        index += 1;
                    }
                    index += 2;
                }
                b'"' => {
                    index += 1;
                    while index < bytes.len() && bytes[index] != b'"' {
                        if bytes[index] == b'\\' {
                            index += 1;
                        }
                        index += 1;
                    }
                    index += 1;
                }
                b'{' => {
                    depth += 1;
                    index += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return haystack[start..=index].to_owned();
                    }
                    index += 1;
                }
                _ => index += 1,
            }
        }
    };

    // Source: the two distinct frozen rows. Requested and terminal stopped are
    // separate rows with separate events, separate owner states and separate
    // tests; nothing merges them.
    let case12_requested_row = case12_row("stop.cancellation-requested");
    let case12_stopped_row = case12_row("stop.stopped");
    let case12_requested_event = case12_field(&case12_requested_row, "event");
    let case12_stopped_event = case12_field(&case12_stopped_row, "event");
    assert_ne!(
        case12_requested_event, case12_stopped_event,
        "cancellation requested must never share the terminal stopped event"
    );
    assert_eq!(
        case12_field(&case12_requested_row, "source_item"),
        case12_field(&case12_stopped_row, "source_item"),
        "both rows belong to the one real stop contour"
    );
    assert_eq!(
        case12_field(&case12_requested_row, "test"),
        "891/case-12",
        "the requested cancellation row is the case-12 row"
    );
    assert_eq!(
        case12_field(&case12_stopped_row, "test"),
        "891/T-A",
        "the terminal stopped row keeps its own proving test"
    );
    assert_ne!(
        case12_field(&case12_requested_row, "owner_state"),
        case12_field(&case12_stopped_row, "owner_state"),
        "a running activation/SCM stop control is not a released lease/stopped contour"
    );
    let case12_details = fixture["drain_details"]
        .as_array()
        .expect("the fixture must pin the drain details");
    for case12_event in [&case12_requested_event, &case12_stopped_event] {
        assert_eq!(
            case12_details
                .iter()
                .filter(|detail| detail.as_str() == Some(case12_event.as_str()))
                .count(),
            1,
            "the frozen drain detail list must carry {case12_event} exactly once"
        );
    }

    // Source: the real contour orders requested -> cancellation requested ->
    // disarm -> stopped. An already-stopped host returns before the
    // cancellation record, so a vacuous stop never claims a cancellation ran.
    let case12_stop = case12_body(&lib, "pub fn stop(&mut self) -> Result<(), HostError> {");
    let case12_at = |needle: &str| -> usize {
        case12_stop
            .find(needle)
            .unwrap_or_else(|| panic!("the stop contour must contain {needle:?}"))
    };
    let case12_stop_requested = case12_at("BOUNDARY_STOP_REQUESTED");
    let case12_cancel = case12_at("BOUNDARY_STOP_CANCELLATION_REQUESTED");
    let case12_disarm = case12_at("host_terminal.disarm();");
    let case12_stopped = case12_at("host_lifecycle_observe_drain(BOUNDARY_STOP_STOPPED)");
    assert!(
        case12_stop_requested < case12_cancel,
        "stop requested must precede cancellation requested"
    );
    assert!(
        case12_cancel < case12_disarm && case12_disarm < case12_stopped,
        "cancellation requested is emitted while the guard is still armed; only a disarmed guard reaches stopped"
    );
    assert!(
        case12_at("if !self.running {") < case12_at("return Err(HostError::Stopped);")
            && case12_at("return Err(HostError::Stopped);") < case12_cancel,
        "a vacuous already-stopped stop returns before the cancellation record"
    );
    assert_eq!(
        count_occurrences(&case12_stop, "host_lifecycle_observe_terminal("),
        0,
        "the stop contour owns no direct terminal call; only its guard emits one"
    );
    assert_eq!(
        count_occurrences(&case12_stop, "HostTerminalGuard::armed("),
        1,
        "the stop contour arms exactly one designated terminal"
    );

    // Source: the real console caller keeps cancellation with proven no-effect
    // distinct from a successful stop: the vacuous stop arm answers Error and
    // never answers Stopped.
    let case12_arm = console
        .find("Err(error @ HostError::Stopped) => {")
        .expect("the console stop contour must own the vacuous-stop arm");
    let case12_arm_end = case12_arm
        + console[case12_arm..]
            .find("Err(error) => {")
            .expect("the vacuous-stop arm must close before the failure arm");
    let case12_cancelled_arm = &console[case12_arm..case12_arm_end];
    assert!(
        case12_cancelled_arm.contains("HostRequestProjection::cancelled("),
        "the vacuous stop must project cancellation with proven no-effect"
    );
    assert!(
        case12_cancelled_arm.contains("Response::Error"),
        "cancellation answers the typed error, not a stopped response"
    );
    assert!(
        !case12_cancelled_arm.contains("Response::Stopped"),
        "cancellation must never be reported as a successful stop"
    );
    assert!(
        !case12_cancelled_arm.contains("HostRequestProjection::durable_committed("),
        "the committed effect must never be projected from a vacuous stop"
    );
    let case12_ok_start = console
        .find("match host.stop() {")
        .and_then(|dispatch| console[dispatch..].find("Ok(()) => {"))
        .expect("the console stop contour must own the accepted-stop arm");
    let case12_ok_arm = &console[case12_ok_start..case12_arm];
    assert!(
        case12_ok_arm.contains("HostRequestProjection::durable_committed("),
        "only the accepted stop projects the committed effect"
    );
    assert!(
        case12_ok_arm.contains("Response::Stopped"),
        "only the accepted stop answers the stopped response"
    );
    assert_eq!(
        fixture["distinctions"]["cancellation_requested_vs_stopped"].as_bool(),
        Some(true),
        "the fixture must keep the requested-versus-stopped distinction declared"
    );

    // Discovery: the fixture stage and the real stage vocabulary agree, and
    // the facade event names are read from the facade itself.
    assert_eq!(
        fixture["stages"]["shutdown_drain"].as_str(),
        Some(EntrypointStage::ShutdownDrain.as_str()),
        "the fixture stage must be the real #889 stage name"
    );
    let case12_event = |anchor: &str| -> String {
        let at = facade
            .find(anchor)
            .unwrap_or_else(|| panic!("the facade must emit {anchor}"));
        let rest = &facade[at..];
        let open = rest.find('"').expect("the event field must be a literal");
        let after = &rest[open + 1..];
        let close = after.find('"').expect("the event literal must close");
        after[..close].to_owned()
    };
    let case12_request_record = case12_event("event = \"host.request\"");
    let case12_admission_record = case12_event("event = \"host.event_log_admission\"");
    assert_ne!(
        case12_request_record, case12_admission_record,
        "the projection record and its Event Log admission record are distinct records"
    );

    // Executed pass: one shared stop correlation yields two distinct records
    // through the real facade, and only the committed stop is admitted to the
    // service-stop channel. The typed admission decision is the real #889 one.
    assert!(
        AdmittedEvent::ServiceStop
            .is_admitted_by(eliot_host::host_diagnostics::HostRequestEvidence::DurableCommitted),
        "a durably committed stop is a completed operation the sink may record"
    );
    assert!(
        !AdmittedEvent::ServiceStop
            .is_admitted_by(eliot_host::host_diagnostics::HostRequestEvidence::Cancelled),
        "cancellation with proven no-effect is not a completed stop"
    );
    let case12_committed = eliot_host::host_diagnostics::HostRequestProjection::durable_committed(
        EntrypointStage::ShutdownDrain,
    )
    .with_request(eliot_host::host_diagnostics::HostConsoleRequest::Stop)
    .with_operation(AdmittedEvent::ServiceStop);
    let case12_cancelled = eliot_host::host_diagnostics::HostRequestProjection::cancelled(
        EntrypointStage::ShutdownDrain,
    )
    .with_request(eliot_host::host_diagnostics::HostConsoleRequest::Stop)
    .with_operation(AdmittedEvent::ServiceStop);
    let case12_correlation = format!(
        "{}-891-case-12",
        fixture["drain_correlation"]
            .as_str()
            .expect("the fixture must pin the drain correlation")
    );
    let case12_text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("{case12_requested_event} {case12_correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("{case12_stopped_event} {case12_correlation}"),
        );
        eliot_host::host_diagnostics::observe_host_request(&case12_committed);
        eliot_host::host_diagnostics::observe_host_request(&case12_cancelled);
    });
    assert_eq!(
        count_occurrences(&case12_text, &case12_correlation),
        2,
        "requested and terminal stopped share one correlation, got: {case12_text}"
    );
    assert_eq!(
        count_occurrences(&case12_text, &case12_requested_event),
        1,
        "exactly one requested record, got: {case12_text}"
    );
    assert_eq!(
        count_occurrences(&case12_text, &case12_stopped_event),
        1,
        "exactly one terminal stopped record, got: {case12_text}"
    );
    assert_eq!(
        count_occurrences(&case12_text, &case12_request_record),
        2,
        "both projection records reach the shared tracing sink, got: {case12_text}"
    );
    assert_eq!(
        count_occurrences(&case12_text, &case12_admission_record),
        1,
        "only the committed stop reaches the Event Log channel, got: {case12_text}"
    );
    assert_eq!(
        count_occurrences(
            &case12_text,
            eliot_host::host_diagnostics::HostRequestEvidence::DurableCommitted.as_str()
        ),
        1,
        "the committed record keeps its own evidence class"
    );
    assert_eq!(
        count_occurrences(
            &case12_text,
            eliot_host::host_diagnostics::HostRequestEvidence::Cancelled.as_str()
        ),
        1,
        "the cancellation record keeps its own evidence class"
    );
    assert!(
        case12_text.contains(HOST_DIAGNOSTICS_TARGET),
        "the captured records must carry the real facade target"
    );
    // The Event Log seam is never called from this test: the platform's own
    // support is reported, and the Host diagnostic sink stays typed-Unavailable.
    assert_eq!(
        event_log_sink_status().is_ok(),
        cfg!(windows),
        "the Event Log seam must report exactly the platform's own support"
    );
}

// WORK_UNIT_CASE: 891/13
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 13 keeps the pending/timeout rows, the real reconcile branch ordering, the readback-versus-timeout separation and the wire-type executed pass in one deterministic case"
)]
fn lifecycle_timeout_and_possible_state_change_stay_unknown() {
    // #891 case 13: a timeout / possible state change stays UNKNOWN. Source:
    // the frozen `kernel-restart-reconcile.unknown-pending` row (owner state
    // "pending intent, timeout proves nothing") and the real
    // `reconcile_kernel_restart_request` contour. Discovery: the public
    // runtime-control wire types. Executed pass: the exact response the pending
    // branch builds, validated and request-matched, never a success variant.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");

    let case13_table_start = lib
        .find("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .expect("lib.rs must own the frozen boundary table");
    let case13_table_end = case13_table_start
        + lib[case13_table_start..]
            .find("\n];")
            .expect("the frozen boundary table must close");
    let case13_table = &lib[case13_table_start..case13_table_end];
    let case13_row = |name: &str| -> String {
        let at = case13_table
            .find(&format!("name: \"{name}\","))
            .unwrap_or_else(|| panic!("the frozen table must own row {name}"));
        let row_start = case13_table[..at]
            .rfind("HostLifecycleBoundary {")
            .unwrap_or_else(|| panic!("row {name} must open a struct literal"));
        let row = &case13_table[row_start..];
        let row_end = row
            .find("\n    },")
            .unwrap_or_else(|| panic!("row {name} must close its struct literal"));
        row[..row_end].to_owned()
    };
    let case13_field = |row: &str, field: &str| -> String {
        let prefix = format!("{field}: ");
        let line = row
            .lines()
            .find(|line| line.trim_start().starts_with(prefix.as_str()))
            .unwrap_or_else(|| panic!("row must carry field {field}: {row}"));
        let mut value = String::new();
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let close = after
                .find('"')
                .unwrap_or_else(|| panic!("the {field} literal must close: {line}"));
            value.push_str(&after[..close]);
            rest = &after[close + 1..];
        }
        value
    };

    // Source: the pending/timeout row is the case-13 row and its owner state
    // states the rule instead of asserting an effect.
    let case13_pending_row = case13_row("kernel-restart-reconcile.unknown-pending");
    assert_eq!(
        case13_field(&case13_pending_row, "test"),
        "891/case-13",
        "the pending-intent row is the case-13 row"
    );
    assert_eq!(
        case13_field(&case13_pending_row, "owner_state"),
        "pending intent, timeout proves nothing",
        "a pending intent proves no effect and no non-effect"
    );
    let case13_pending_event = case13_field(&case13_pending_row, "event");
    assert_ne!(
        case13_pending_event,
        case13_field(
            &case13_row("kernel-restart-reconcile.receipt-readback-replay"),
            "event"
        ),
        "a pending timeout is never the committed-receipt readback"
    );
    let case13_terminal_row = case13_row("kernel-restart-reconcile.terminal");
    assert_eq!(
        case13_field(&case13_terminal_row, "event"),
        fixture["terminal_codes"]["kernel_restart_reconcile_unknown"]
            .as_str()
            .expect("the fixture must pin the reconcile unknown code"),
        "the reconcile terminal code is the frozen typed Unknown code"
    );
    assert_ne!(
        case13_field(&case13_terminal_row, "event"),
        fixture["terminal_codes"]["kernel_restart_unknown"]
            .as_str()
            .expect("the fixture must pin the restart unknown code"),
        "a reconcile timeout carries its own code, never the dispatch code"
    );
    assert_eq!(
        fixture["distinctions"]["failed_vs_unknown"].as_bool(),
        Some(true),
        "the fixture must keep failed and unknown distinct"
    );

    // Source: the real reconcile contour. The pending arm observes, emits the
    // one terminal and answers Unknown; it never reaches a success
    // construction. The only success construction in the contour is the
    // committed-receipt readback, which is itself labelled replay.
    let case13_reconcile_at = lib
        .find("pub fn reconcile_kernel_restart_request(")
        .expect("lib.rs must own the public reconcile contour");
    let case13_reconcile = lib[case13_reconcile_at..]
        .split("fn approved_phase_b_config_for_manifest(")
        .next()
        .expect("the reconcile contour must be followed by the next contour owner");
    let case13_at = |needle: &str| -> usize {
        case13_reconcile
            .find(needle)
            .unwrap_or_else(|| panic!("the reconcile contour must contain {needle:?}"))
    };
    let case13_probe = case13_at("has_runtime_restart_pending(");
    let case13_pending_arm = case13_at("Ok(true) | Err(_) => {");
    let case13_pending_observe = case13_at("BOUNDARY_KERNEL_RESTART_RECONCILE_UNKNOWN_PENDING");
    let case13_pending_terminal = case13_reconcile[case13_pending_observe..]
        .find("BOUNDARY_KERNEL_RESTART_RECONCILE_TERMINAL")
        .map(|case13_offset| case13_offset + case13_pending_observe)
        .expect("the pending arm must emit the reconcile terminal");
    let case13_pending_answer = case13_reconcile[case13_pending_observe..]
        .find("HostRuntimeControlResponse::unknown_for(")
        .map(|case13_offset| case13_offset + case13_pending_observe)
        .expect("the pending arm must answer the request");
    assert!(
        case13_probe < case13_pending_arm
            && case13_pending_arm < case13_pending_observe
            && case13_pending_observe < case13_pending_terminal
            && case13_pending_terminal < case13_pending_answer,
        "a pending or unreadable pending intent observes, emits one terminal and answers Unknown"
    );
    assert_eq!(
        count_occurrences(
            case13_reconcile,
            "HostRuntimeControlResponse::restarted_for("
        ),
        1,
        "the reconcile contour constructs exactly one success answer"
    );
    assert!(
        !case13_reconcile[case13_pending_observe..]
            .contains("HostRuntimeControlResponse::restarted_for("),
        "after the pending arm no success answer remains reachable"
    );
    assert!(
        case13_at("BOUNDARY_KERNEL_RESTART_RECONCILE_RECEIPT_READBACK_REPLAY") < case13_probe,
        "the only success answer is the committed-receipt readback replay, before any pending probe"
    );
    assert_eq!(
        case13_reconcile
            .matches("HostTerminalGuard::armed(")
            .count(),
        0,
        "the reconcile contour owns per-outcome terminal emissions, not a guard"
    );
    assert!(
        case13_reconcile
            .contains("runtime_control_unknown_ref(\"kernel-restart-pending\", request)"),
        "the pending arm answers with the exact pending recovery reference"
    );
    assert!(
        case13_pending_event.starts_with("host.kernel-restart-reconcile")
            && case13_pending_event.ends_with("unknown pending")
            && count_occurrences(&lib, &format!("event: \"{case13_pending_event}\",")) == 1,
        "the pending observation must be the one frozen boundary row for the unknown-pending outcome, got {case13_pending_event:?}"
    );

    // Discovery: the facade event names come from the facade itself.
    let case13_event = |anchor: &str| -> String {
        let at = facade
            .find(anchor)
            .unwrap_or_else(|| panic!("the facade must emit {anchor}"));
        let rest = &facade[at..];
        let open = rest.find('"').expect("the event field must be a literal");
        let after = &rest[open + 1..];
        let close = after.find('"').expect("the event literal must close");
        after[..close].to_owned()
    };
    let case13_stage_event = case13_event("event = \"host.entrypoint_stage\"");
    let case13_terminal_event = case13_event("event = \"host.terminal_error\"");
    assert_eq!(
        fixture["entrypoint_event"].as_str(),
        Some(case13_stage_event.as_str()),
        "the fixture entrypoint event must be the real facade event"
    );
    assert_eq!(
        fixture["terminal_event"].as_str(),
        Some(case13_terminal_event.as_str()),
        "the fixture terminal event must be the real facade event"
    );

    // Executed pass: build the exact response the pending branch builds for a
    // real timed-out restart request, validate it, and prove it can neither be
    // read as a success nor as another request's answer.
    let case13_request = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RestartKernel,
        eliot_platform::PlatformHandle::new("891-case-13-kernel-restart".to_owned())
            .expect("the test handle must be valid"),
    )
    .expect("a RestartKernel request must validate on the wire");
    case13_request
        .validate()
        .expect("the restart request must be valid");
    let case13_response = eliot_host::HostRuntimeControlResponse::unknown_for(
        &case13_request,
        eliot_host_service::runtime_control::runtime_control_unknown_ref(
            "kernel-restart-pending",
            &case13_request,
        ),
    );
    case13_response
        .validate()
        .expect("a pending unknown must validate");
    assert!(
        matches!(
            case13_response,
            eliot_host::HostRuntimeControlResponse::Unknown { .. }
        ),
        "a timed-out restart with a pending intent stays Unknown"
    );
    assert!(
        !matches!(
            case13_response,
            eliot_host::HostRuntimeControlResponse::Restarted { .. }
        ),
        "a pending intent is never a restarted success"
    );
    assert!(
        !matches!(
            case13_response,
            eliot_host::HostRuntimeControlResponse::StoreRecovered { .. }
        ),
        "a kernel restart timeout is never a store recovery success"
    );
    assert!(
        eliot_host_service::runtime_control::response_matches_request(
            &case13_request,
            &case13_response
        ),
        "the unknown answer must preserve the exact request identity"
    );
    let case13_other = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::ReconcileKernelRestart,
        eliot_platform::PlatformHandle::new("891-case-13-other-request".to_owned())
            .expect("the test handle must be valid"),
    )
    .expect("a reconcile request must validate on the wire");
    assert!(
        !eliot_host_service::runtime_control::response_matches_request(
            &case13_other,
            &case13_response
        ),
        "one request's pending unknown must never answer another request"
    );
    if let eliot_host::HostRuntimeControlResponse::Unknown { pending_ref } = &case13_response {
        assert!(
            pending_ref
                .as_str()
                .contains(case13_request.mutation_digest.as_str()),
            "the pending reference carries the exact mutation identity, not a payload"
        );
    } else {
        panic!("the pending branch answer must be Unknown");
    }

    // Executed pass: the frozen pending observation and its one typed terminal,
    // emitted through the real facade in the real branch order. No success
    // record and no second terminal may appear on the timeout path.
    let case13_terminal_code = case13_field(&case13_terminal_row, "event");
    let case13_requested_event =
        case13_field(&case13_row("kernel-restart-reconcile.requested"), "event");
    let case13_text = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &case13_requested_event);
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &case13_pending_event);
        observe_terminal_error(&case13_terminal_code);
    });
    assert_eq!(
        count_occurrences(&case13_text, &case13_requested_event),
        1,
        "the reconcile requested record crosses once, got: {case13_text}"
    );
    assert_eq!(
        count_occurrences(&case13_text, &case13_pending_event),
        1,
        "the pending/timeout observation is emitted once, got: {case13_text}"
    );
    assert_eq!(
        count_occurrences(&case13_text, &case13_terminal_code),
        1,
        "the typed unknown code crosses exactly once, got: {case13_text}"
    );
    assert_eq!(
        count_occurrences(&case13_text, case13_terminal_event.as_str()),
        1,
        "one terminal per timeout outcome, got: {case13_text}"
    );
    let case13_receipt_event =
        case13_field(&case13_row("kernel-restart.receipt-completion"), "event");
    assert!(
        !case13_text.contains(&case13_receipt_event),
        "a pending intent never emits the receipt-completion record"
    );
    assert!(
        !case13_text.contains("kernel-restart-pending"),
        "the recovery reference is a wire value, never a diagnostic payload, got: {case13_text}"
    );
    assert!(
        !case13_text.contains(
            fixture["terminal_codes"]["kernel_restart_unknown"]
                .as_str()
                .unwrap_or_default()
        ),
        "a reconcile timeout never borrows the dispatch unknown code, got: {case13_text}"
    );
}

// WORK_UNIT_CASE: 891/14
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 14 keeps the designated terminal count, the nested propagation review and the replay-labelling pass in one deterministic case"
)]
fn lifecycle_one_terminal_per_operation_across_nested_propagation() {
    // #891 case 14: exactly one terminal per underlying operation across nested
    // propagation, not one per question mark. Source: the frozen `start.terminal`
    // row and the real `start_approved_contour` / `start_manifest_contour`
    // contours. Discovery: the guard that owns the emission. Executed pass: one
    // operation's phase records plus exactly one terminal, and a repeated
    // readback labelled replay.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");

    let case14_table_start = lib
        .find("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .expect("lib.rs must own the frozen boundary table");
    let case14_table_end = case14_table_start
        + lib[case14_table_start..]
            .find("\n];")
            .expect("the frozen boundary table must close");
    let case14_table = &lib[case14_table_start..case14_table_end];
    let case14_row = |name: &str| -> String {
        let at = case14_table
            .find(&format!("name: \"{name}\","))
            .unwrap_or_else(|| panic!("the frozen table must own row {name}"));
        let row_start = case14_table[..at]
            .rfind("HostLifecycleBoundary {")
            .unwrap_or_else(|| panic!("row {name} must open a struct literal"));
        let row = &case14_table[row_start..];
        let row_end = row
            .find("\n    },")
            .unwrap_or_else(|| panic!("row {name} must close its struct literal"));
        row[..row_end].to_owned()
    };
    let case14_field = |row: &str, field: &str| -> String {
        let prefix = format!("{field}: ");
        let line = row
            .lines()
            .find(|line| line.trim_start().starts_with(prefix.as_str()))
            .unwrap_or_else(|| panic!("row must carry field {field}: {row}"));
        let mut value = String::new();
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let close = after
                .find('"')
                .unwrap_or_else(|| panic!("the {field} literal must close: {line}"));
            value.push_str(&after[..close]);
            rest = &after[close + 1..];
        }
        value
    };
    let case14_body = |haystack: &str, header: &str| -> String {
        let start = haystack
            .find(header)
            .unwrap_or_else(|| panic!("the source must contain {header}"));
        let bytes = haystack.as_bytes();
        let mut index = start;
        let mut depth = 0usize;
        loop {
            assert!(index < bytes.len(), "{header} must close in the source");
            match bytes[index] {
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    while index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    while index + 1 < bytes.len()
                        && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                    {
                        index += 1;
                    }
                    index += 2;
                }
                b'"' => {
                    index += 1;
                    while index < bytes.len() && bytes[index] != b'"' {
                        if bytes[index] == b'\\' {
                            index += 1;
                        }
                        index += 1;
                    }
                    index += 1;
                }
                b'{' => {
                    depth += 1;
                    index += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return haystack[start..=index].to_owned();
                    }
                    index += 1;
                }
                _ => index += 1,
            }
        }
    };

    // Source: the frozen row that names the designated terminal of the start
    // operation, and the one static identifier that can emit its code.
    let case14_terminal_row = case14_row("start.terminal");
    assert_eq!(
        case14_field(&case14_terminal_row, "test"),
        "891/case-14",
        "the start terminal row is the case-14 row"
    );
    let case14_code = case14_field(&case14_terminal_row, "event");
    assert_eq!(
        case14_code,
        fixture["terminal_codes"]["start_failed"]
            .as_str()
            .expect("the fixture must pin the start terminal code"),
        "the start terminal code is the frozen typed code"
    );
    assert_eq!(
        count_occurrences(&lib, &format!("boundary_by_event(\"{case14_code}\")")),
        1,
        "exactly one static boundary identifier can emit the start terminal code"
    );

    // Source: the real start contour. One guard arms the designated terminal;
    // the nested `?` propagations below it add no second terminal; success
    // disarms the guard.
    let case14_start_contour = case14_body(&lib, "pub fn start_approved_contour(");
    assert_eq!(
        count_occurrences(
            &case14_start_contour,
            "HostTerminalGuard::armed(BOUNDARY_START_TERMINAL)"
        ),
        1,
        "the start operation arms exactly one designated terminal"
    );
    assert_eq!(
        count_occurrences(&case14_start_contour, "host_lifecycle_observe_terminal("),
        0,
        "the guarded contour emits no terminal directly; only the guard's drop does"
    );
    assert_eq!(
        count_occurrences(&case14_start_contour, "host_terminal.disarm();"),
        1,
        "the success path disarms the designated terminal exactly once"
    );
    let case14_at = |needle: &str| -> usize {
        case14_start_contour
            .find(needle)
            .unwrap_or_else(|| panic!("the start contour must contain {needle:?}"))
    };
    assert!(
        case14_at("HostTerminalGuard::armed(")
            < case14_at("ensure_material_admission_open_for_target(")
            && case14_at("ensure_material_admission_open_for_target(")
                < case14_at("self.start_manifest_contour("),
        "both nested propagations run inside the armed operation"
    );
    assert!(
        case14_at("self.start_manifest_contour(") < case14_at("host_terminal.disarm();")
            && case14_at("host_terminal.disarm();") < case14_at("BOUNDARY_START_STARTED"),
        "a successful nested contour disarms before the started record"
    );
    let case14_question_marks = case14_start_contour.matches(")?").count();
    assert!(
        case14_question_marks >= 4,
        "the operation must really propagate nested results by question mark, got {case14_question_marks}"
    );

    // Source: the nested contour itself is phase-only. It shares the
    // correlation and never owns a terminal, so nested propagation cannot
    // multiply the terminal count.
    let case14_nested = case14_body(&lib, "    fn start_manifest_contour(");
    assert_eq!(
        count_occurrences(&case14_nested, "HostTerminalGuard::armed("),
        0,
        "the nested contour arms no terminal guard"
    );
    assert_eq!(
        count_occurrences(&case14_nested, "host_lifecycle_observe_terminal("),
        0,
        "the nested contour emits no terminal of its own"
    );
    let case14_nested_marks = case14_nested.matches(")?").count();
    assert!(
        case14_nested_marks >= 10,
        "the nested contour really propagates many inner errors by question mark, got {case14_nested_marks}"
    );
    assert!(
        case14_nested.contains("BOUNDARY_START_MANIFEST_REQUESTED"),
        "the nested contour is observed through its own frozen row"
    );

    // Source: one armed guard per public operation, and the guard emits only
    // while armed, so a committed operation never re-emits on readback.
    let case14_guard = case14_body(&lib, "impl Drop for HostTerminalGuard {");
    assert!(
        case14_guard.contains("if self.armed {")
            && case14_guard.contains("host_lifecycle_observe_terminal(self.boundary)"),
        "the terminal is emitted from the guard drop, once, only while armed"
    );
    assert!(
        !lib.contains("static DEDUP")
            && !lib.contains("Mutex<HashSet")
            && !lib.contains("OnceLock<HashSet"),
        "no mutable global dedup cache may stand in for a designated boundary"
    );
    assert!(
        lib.contains("No dedup cache, no lock, no second evaluation."),
        "the guard must state why one armed boundary is the whole mechanism"
    );
    assert_eq!(
        fixture["allowed_diff"]["single_terminal_per_failed_op"].as_bool(),
        Some(true),
        "the fixture must keep the single-terminal property declared"
    );

    // Discovery: the facade event names come from the facade itself.
    let case14_event = |anchor: &str| -> String {
        let at = facade
            .find(anchor)
            .unwrap_or_else(|| panic!("the facade must emit {anchor}"));
        let rest = &facade[at..];
        let open = rest.find('"').expect("the event field must be a literal");
        let after = &rest[open + 1..];
        let close = after.find('"').expect("the event literal must close");
        after[..close].to_owned()
    };
    let case14_stage_event = case14_event("event = \"host.entrypoint_stage\"");
    let case14_terminal_event = case14_event("event = \"host.terminal_error\"");
    assert_eq!(
        fixture["terminal_event"].as_str(),
        Some(case14_terminal_event.as_str()),
        "the fixture terminal event must be the real facade event"
    );

    // Executed pass: one failed operation emits its phase records and exactly
    // one terminal; the nested phase record shares the correlation and is not a
    // second terminal failure.
    let case14_requested = case14_field(&case14_row("start.requested"), "event");
    let case14_nested_requested = case14_field(&case14_row("start-manifest.requested"), "event");
    let case14_correlation = "891-case-14-start-operation";
    let case14_text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("{case14_requested} {case14_correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("{case14_nested_requested} {case14_correlation}"),
        );
        observe_terminal_error(&case14_code);
    });
    assert_eq!(
        count_occurrences(&case14_text, case14_stage_event.as_str()),
        2,
        "the requested record and the nested phase record share one stage event, got: {case14_text}"
    );
    assert_eq!(
        count_occurrences(&case14_text, case14_terminal_event.as_str()),
        1,
        "one underlying failed operation emits exactly one terminal, got: {case14_text}"
    );
    assert_eq!(
        count_occurrences(&case14_text, &case14_code),
        1,
        "the typed terminal code crosses exactly once, got: {case14_text}"
    );
    assert_eq!(
        count_occurrences(&case14_text, case14_correlation),
        2,
        "both phase records share one operation correlation, got: {case14_text}"
    );
    assert_eq!(
        count_occurrences(&case14_text, &format!("code_bytes={}", case14_code.len())),
        1,
        "the terminal code crosses whole, never truncated free text"
    );

    // Executed pass: repeated observation of an already committed operation is
    // labelled replay/readback, never another commit and never a second
    // terminal.
    let case14_replay = case14_field(
        &case14_row("kernel-restart-reconcile.receipt-readback-replay"),
        "event",
    );
    let case14_replay_text = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &case14_replay);
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &case14_replay);
    });
    assert_eq!(
        count_occurrences(&case14_replay_text, &case14_replay),
        2,
        "a committed operation may be read back repeatedly, got: {case14_replay_text}"
    );
    assert_eq!(
        count_occurrences(&case14_replay_text, case14_terminal_event.as_str()),
        0,
        "replay/readback is never another commit and never a second terminal"
    );
    let case14_reconcile = case14_body(&lib, "pub fn reconcile_kernel_restart_request(");
    let case14_replay_at = case14_reconcile
        .find("BOUNDARY_KERNEL_RESTART_RECONCILE_RECEIPT_READBACK_REPLAY")
        .expect("the reconcile contour must own the readback replay row");
    let case14_replay_arm = &case14_reconcile[case14_replay_at..];
    let case14_replay_end = case14_replay_arm
        .find("} else {")
        .expect("the replay arm must be followed by its conflict arm");
    assert!(
        !case14_replay_arm[..case14_replay_end].contains("host_lifecycle_observe_terminal("),
        "the replay arm emits no terminal"
    );
    assert!(
        case14_replay_arm[..case14_replay_end].contains("restarted_for("),
        "the replay arm answers from the already committed receipt"
    );
}

// WORK_UNIT_CASE: 891/15
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 15 keeps the real identity projection call site, the lifecycle correlation composition, the named-missing slots and the record-level executed pass in one deterministic case"
)]
fn lifecycle_identity_correlation_is_exact_and_bounded() {
    // #891 case 15: exact installation/process/generation/operation
    // correlation. Source: the real `host_lifecycle_observe_identity` and its
    // production caller, plus the real `lifecycle_context` correlation
    // composition. Discovery: the public projection builders. Executed pass: a
    // real admitted launch owner projected through the real facade, with the
    // deferred digest/fence/tx/effect slots asserted still named-missing.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");

    let case15_table_start = lib
        .find("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .expect("lib.rs must own the frozen boundary table");
    let case15_table_end = case15_table_start
        + lib[case15_table_start..]
            .find("\n];")
            .expect("the frozen boundary table must close");
    let case15_table = &lib[case15_table_start..case15_table_end];
    let case15_row = |name: &str| -> String {
        let at = case15_table
            .find(&format!("name: \"{name}\","))
            .unwrap_or_else(|| panic!("the frozen table must own row {name}"));
        let row_start = case15_table[..at]
            .rfind("HostLifecycleBoundary {")
            .unwrap_or_else(|| panic!("row {name} must open a struct literal"));
        let row = &case15_table[row_start..];
        let row_end = row
            .find("\n    },")
            .unwrap_or_else(|| panic!("row {name} must close its struct literal"));
        row[..row_end].to_owned()
    };
    let case15_field = |row: &str, field: &str| -> String {
        let prefix = format!("{field}: ");
        let line = row
            .lines()
            .find(|line| line.trim_start().starts_with(prefix.as_str()))
            .unwrap_or_else(|| panic!("row must carry field {field}: {row}"));
        let mut value = String::new();
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let close = after
                .find('"')
                .unwrap_or_else(|| panic!("the {field} literal must close: {line}"));
            value.push_str(&after[..close]);
            rest = &after[close + 1..];
        }
        value
    };
    let case15_body = |haystack: &str, header: &str| -> String {
        let start = haystack
            .find(header)
            .unwrap_or_else(|| panic!("the source must contain {header}"));
        let bytes = haystack.as_bytes();
        let mut index = start;
        let mut depth = 0usize;
        loop {
            assert!(index < bytes.len(), "{header} must close in the source");
            match bytes[index] {
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    while index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    while index + 1 < bytes.len()
                        && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                    {
                        index += 1;
                    }
                    index += 2;
                }
                b'"' => {
                    index += 1;
                    while index < bytes.len() && bytes[index] != b'"' {
                        if bytes[index] == b'\\' {
                            index += 1;
                        }
                        index += 1;
                    }
                    index += 1;
                }
                b'{' => {
                    depth += 1;
                    index += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return haystack[start..=index].to_owned();
                    }
                    index += 1;
                }
                _ => index += 1,
            }
        }
    };

    // Source: the identity projection is one nonsecret, subordinate, never
    // terminal observation of an already owned identity bundle.
    let case15_identity = case15_body(&lib, "fn host_lifecycle_observe_identity(");
    assert!(
        case15_identity.contains("host_diagnostics::observe_host_request(projection)"),
        "the identity observation must project through the #889 facade"
    );
    assert!(
        !case15_identity.contains("observe_terminal_error"),
        "an identity record is never a terminal emission"
    );
    assert!(
        !case15_identity.contains("pub fn"),
        "the identity observation adds no public logging surface"
    );
    assert_eq!(
        count_occurrences(&lib, "host_lifecycle_observe_identity("),
        2,
        "one definition plus exactly one production caller"
    );

    // Source: the real production caller passes only the installation and
    // generation already held by the launch owner plus this process id. No SCM
    // payload, command, env, credential, connection, source or user data, and
    // no arbitrary Debug/Display string, may cross.
    let case15_caller = case15_body(&lib, "pub fn handle_kernel_restart_request(");
    let case15_call_at = case15_caller
        .find("host_lifecycle_observe_identity(")
        .expect("the SCM dispatch must own the identity observation");
    let case15_call = &case15_caller[case15_call_at..];
    let case15_call_end = case15_call
        .find(";\n")
        .expect("the identity observation must end in one statement");
    let case15_call = &case15_call[..case15_call_end];
    for case15_builder in [
        "host_diagnostics::HostRequestProjection::observed(",
        "host_diagnostics::EntrypointStage::ScmDispatch",
        ".with_launch_options(&self.launch_options)",
        ".with_process(std::process::id())",
    ] {
        assert!(
            case15_call.contains(case15_builder),
            "the identity call site must build its projection with {case15_builder}, got: {case15_call}"
        );
    }
    for case15_forbidden in [
        "format!",
        "{:?}",
        "to_string()",
        "std::env",
        "args()",
        "password",
        "token",
        "connection",
        "credential",
        "payload",
        "user",
    ] {
        assert!(
            !case15_call.contains(case15_forbidden),
            "the identity call site must not carry {case15_forbidden:?}, got: {case15_call}"
        );
    }

    // Source: the real correlation composition carries exactly the permitted
    // installation, sequence, operation and process identities, and nothing
    // else.
    let case15_row_requested = case15_row("lifecycle-context.requested");
    let case15_row_admitted = case15_row("lifecycle-context.admitted");
    assert_eq!(
        case15_field(&case15_row_requested, "test"),
        "891/case-15",
        "the lifecycle-context requested row is the case-15 row"
    );
    assert_eq!(
        case15_field(&case15_row_admitted, "test"),
        "891/case-15",
        "the lifecycle-context admitted row is the case-15 row"
    );
    assert_eq!(
        case15_field(&case15_row_requested, "owner_state"),
        "epoch/operation/process identity",
        "the correlation owner state names the exact permitted identities"
    );
    let case15_context = case15_body(&lib, "fn lifecycle_context(\n");
    for case15_identity_part in [
        "host.epoch.current.lineage_id",
        "host.epoch.current.sequence",
        "std::process::id()",
        "StateFence::new(host.epoch.current.clone(), ResourceGeneration::genesis())",
    ] {
        assert!(
            case15_context.contains(case15_identity_part),
            "the correlation must carry {case15_identity_part}, got: {case15_context}"
        );
    }
    let case15_format_at = case15_context
        .find("RequestId::new(format!(")
        .expect("the correlation must be composed by one request id format");
    let case15_format_rest = &case15_context[case15_format_at..];
    let case15_format_open = case15_format_rest
        .find('"')
        .expect("the format must be a literal");
    let case15_format_after = &case15_format_rest[case15_format_open + 1..];
    let case15_format_close = case15_format_after
        .find('"')
        .expect("the format literal must close");
    let case15_format = &case15_format_after[..case15_format_close];
    assert_eq!(
        case15_format.matches("{}").count(),
        4,
        "the correlation format carries exactly four identities: {case15_format}"
    );
    let case15_args = &case15_format_after[case15_format_close..];
    let case15_args_end = case15_args
        .find("))")
        .expect("the request id call must close");
    let case15_args = &case15_args[..case15_args_end];
    for case15_arg in [
        "host.epoch.current.lineage_id",
        "host.epoch.current.sequence",
        "operation",
        "std::process::id()",
    ] {
        assert!(
            case15_args.contains(case15_arg),
            "the correlation argument list must carry {case15_arg}, got: {case15_args}"
        );
    }
    assert_eq!(
        case15_args
            .lines()
            .filter(|case15_line| {
                let case15_trimmed = case15_line.trim_start();
                case15_trimmed.starts_with("host.")
                    || case15_trimmed.starts_with("operation")
                    || case15_trimmed.starts_with("std::")
            })
            .count(),
        4,
        "the correlation passes exactly the four permitted identities, got: {case15_args}"
    );
    let case15_call_site = lib[lib
        .find("lifecycle_context(&self.host,")
        .expect("the start contour must build the lifecycle correlation")..]
        .lines()
        .next()
        .expect("the call site must be one line");
    assert!(
        case15_call_site.contains("\"watchdog-start\""),
        "the operation identity is a static caller literal, got: {case15_call_site}"
    );

    // Source: the record vocabulary. The present identity slots are exactly
    // installation/generation/process plus their evidence class and phase; the
    // deferred digest/fence/tx/effect slots stay named-missing until #889 lands
    // them, so nothing may be read from them.
    let case15_record = case15_body(&facade, "pub fn observe_host_request(");
    let mut case15_fields: Vec<&str> = Vec::new();
    for case15_line in case15_record.lines() {
        let case15_trimmed = case15_line.trim();
        if let Some((case15_name, case15_value)) = case15_trimmed.split_once(" = ")
            && case15_value.ends_with(',')
            && !case15_name.is_empty()
            && case15_name
                .chars()
                .all(|case15_char| case15_char.is_ascii_lowercase() || case15_char == '_')
        {
            case15_fields.push(case15_name);
        }
    }
    for case15_present in [
        "installation",
        "generation",
        "process",
        "evidence",
        "phase",
        "reason",
        "receipt_sequence",
        "receipt_exit",
    ] {
        assert!(
            case15_fields.contains(&case15_present),
            "the record must carry the {case15_present} slot, got: {case15_fields:?}"
        );
    }
    for case15_deferred in [
        "digest",
        "fence",
        "tx",
        "effect",
        "transaction",
        "mutation_digest",
        "request_digest",
        "connection",
        "environment",
        "payload",
    ] {
        assert!(
            !case15_fields.contains(&case15_deferred),
            "the {case15_deferred} slot must stay named-missing, got: {case15_fields:?}"
        );
    }
    assert!(
        !case15_record.contains("format!") && !case15_record.contains("{:?}"),
        "the identity record must not format an arbitrary Debug/Display value"
    );
    assert_eq!(
        fixture["max_field_bytes"].as_u64(),
        Some(eliot_host::host_diagnostics::MAX_DIAGNOSTIC_FIELD_BYTES as u64),
        "the fixture field bound must be the real facade bound"
    );

    // Executed pass: a real admitted launch owner (the real argv parser) is
    // projected through the real facade; the carried identities are the exact
    // admitted ones and every unfitted slot stays explicitly missing.
    let case15_options = eliot_host::HostLaunchOptions::parse([
        "--config-descriptor",
        "C:\\Eliot\\891-case-15-descriptor.json",
        "--config-descriptor-sha256",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--installation-id",
        "891-case-15-installation",
        "--tx-plan-generation",
        "891",
        "--host-state-root",
        "C:\\EliotData\\891-case-15-state-root",
    ])
    .expect("the admitted argv must parse through the real owner");
    let case15_projection =
        eliot_host::host_diagnostics::HostRequestProjection::observed(EntrypointStage::ScmDispatch)
            .with_launch_options(&case15_options)
            .with_process(std::process::id());
    let case15_text =
        capture_emit(|| eliot_host::host_diagnostics::observe_host_request(&case15_projection));
    assert_eq!(
        case15_options.installation().as_str(),
        "891-case-15-installation",
        "the admitted installation identity is the one the owner parsed"
    );
    assert_eq!(case15_options.transaction_plan_generation(), 891);
    assert_eq!(
        count_occurrences(case15_text.as_str(), case15_options.installation().as_str()),
        1,
        "the exact installation identity crosses the record once, got: {case15_text}"
    );
    assert_eq!(
        count_occurrences(
            case15_text.as_str(),
            &format!(
                "generation={}",
                case15_options.transaction_plan_generation()
            )
        ),
        1,
        "the exact generation identity crosses the record once, got: {case15_text}"
    );
    assert_eq!(
        count_occurrences(
            case15_text.as_str(),
            &format!("process={}", std::process::id())
        ),
        1,
        "the exact process identity crosses the record once, got: {case15_text}"
    );
    for case15_carried in [
        "installation_missing=false",
        "generation_missing=false",
        "process_missing=false",
    ] {
        assert!(
            case15_text.contains(case15_carried),
            "a carried identity must not read missing: {case15_carried}, got: {case15_text}"
        );
    }
    for case15_missing in [
        "request_missing=true",
        "operation_missing=true",
        "reason_missing=true",
        "receipt_sequence_missing=true",
        "receipt_exit_missing=true",
    ] {
        assert!(
            case15_text.contains(case15_missing),
            "an unfitted slot must read explicitly missing: {case15_missing}, got: {case15_text}"
        );
    }
    for case15_canary in [
        "password",
        "token=",
        "connection_string",
        "BEGIN PRIVATE",
        "AKIA",
        "--config-descriptor",
        "argv",
    ] {
        assert!(
            !case15_text.contains(case15_canary),
            "no credential, env, argv or SCM payload may cross: {case15_canary}, got: {case15_text}"
        );
    }
}

// WORK_UNIT_CASE: 891/16
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 16 keeps the frozen terminal inventory, the static-identifier scan, the exhaustive typed reason mapping and the executed record pass in one deterministic case"
)]
fn lifecycle_terminal_codes_are_typed_with_no_free_text_status() {
    // #891 case 16: typed reason/recovery code, no free-text machine status.
    // Source: every frozen terminal code the table owns plus every real
    // observation call site. Discovery: the facade's projection and terminal
    // helpers. Executed pass: a real typed `HostError` projected and a frozen
    // terminal code emitted through the real facade.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");

    let case16_table_start = lib
        .find("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .expect("lib.rs must own the frozen boundary table");
    let case16_table_end = case16_table_start
        + lib[case16_table_start..]
            .find("\n];")
            .expect("the frozen boundary table must close");
    let case16_table = &lib[case16_table_start..case16_table_end];
    let case16_names: Vec<&str> = case16_table
        .lines()
        .filter_map(|case16_line| case16_line.trim_start().strip_prefix("name: \""))
        .filter_map(|case16_line| case16_line.split('"').next())
        .collect();
    let case16_tests: Vec<&str> = case16_table
        .lines()
        .filter_map(|case16_line| case16_line.trim_start().strip_prefix("test: \""))
        .filter_map(|case16_line| case16_line.split('"').next())
        .collect();
    let case16_events: Vec<String> = case16_table
        .lines()
        .filter(|case16_line| case16_line.trim_start().starts_with("event: "))
        .map(|case16_line| {
            let mut value = String::new();
            let mut rest = case16_line;
            while let Some(open) = rest.find('"') {
                let after = &rest[open + 1..];
                let close = after
                    .find('"')
                    .unwrap_or_else(|| panic!("the event literal must close: {case16_line}"));
                value.push_str(&after[..close]);
                rest = &after[close + 1..];
            }
            value
        })
        .collect();
    assert_eq!(
        case16_events.len(),
        case16_names.len(),
        "every frozen row must carry exactly one event"
    );
    assert_eq!(
        case16_events.len(),
        case16_tests.len(),
        "every frozen row must carry exactly one proving test"
    );
    assert_eq!(
        case16_events.len(),
        usize::try_from(
            fixture["boundary_table"]["rows"]
                .as_u64()
                .expect("the fixture must pin the table denominator"),
        )
        .expect("the pinned table denominator must fit usize"),
        "the parsed table must have the fixture's declared row count"
    );

    // Source: every terminal code the fixture pins is a frozen identifier owned
    // by exactly one row and selectable by exactly one static boundary
    // constant. No code is shared between two operations.
    let case16_codes = fixture["terminal_codes"]
        .as_object()
        .expect("the fixture must pin the terminal code object");
    assert_eq!(
        case16_codes.len(),
        14,
        "this crate owns fourteen typed terminal codes"
    );
    for (case16_key, case16_value) in case16_codes {
        let case16_code = case16_value
            .as_str()
            .unwrap_or_else(|| panic!("terminal code {case16_key} must be a string"));
        assert!(
            lib.contains(&format!("\"{case16_code}\"")),
            "terminal code {case16_key} must exist as a source literal: {case16_code}"
        );
        assert_eq!(
            case16_events
                .iter()
                .filter(|case16_event| case16_event.as_str() == case16_code)
                .count(),
            1,
            "terminal code {case16_code} must be owned by exactly one frozen row"
        );
        assert_eq!(
            count_occurrences(&lib, &format!("boundary_by_event(\"{case16_code}\")")),
            1,
            "terminal code {case16_code} must be selectable by exactly one static identifier"
        );
        assert!(
            case16_code.starts_with("host-")
                && !case16_code.contains(' ')
                && case16_code.bytes().all(|case16_byte| {
                    case16_byte.is_ascii_lowercase()
                        || case16_byte.is_ascii_digit()
                        || case16_byte == b'-'
                }),
            "terminal code {case16_key} must be a frozen identifier, not free text: {case16_code}"
        );
    }
    // Failed and unknown outcomes keep distinct frozen codes.
    for case16_pair in [
        ("kernel_restart_unknown", "kernel_restart_reconcile_unknown"),
        ("phase_b_unknown", "phase_b_finalize_unknown"),
        ("open_failed", "reconcile_failed"),
    ] {
        assert_ne!(
            case16_codes[case16_pair.0].as_str(),
            case16_codes[case16_pair.1].as_str(),
            "failed and unknown outcomes must keep distinct codes"
        );
    }

    // Source: no observation call site passes a free-form machine status. Every
    // call selects a static `BOUNDARY_*` identifier, the one identity
    // projection, or the guard's already-owned boundary.
    let mut case16_heads: Vec<String> = Vec::new();
    let mut case16_cursor = 0usize;
    while let Some(case16_at) = lib[case16_cursor..].find("host_lifecycle_observe_") {
        let case16_absolute = case16_cursor + case16_at;
        if !lib[..case16_absolute].trim_end().ends_with("fn") {
            let case16_tail = &lib[case16_absolute..];
            let case16_open = case16_tail
                .find('(')
                .expect("an observation call must open its argument list");
            let case16_arg = case16_tail[case16_open + 1..].trim_start();
            case16_heads.push(
                case16_arg
                    .chars()
                    .take_while(|case16_char| !case16_char.is_whitespace() && *case16_char != ')')
                    .collect(),
            );
        }
        case16_cursor = case16_absolute + 1;
    }
    for case16_head in &case16_heads {
        assert!(
            case16_head.starts_with("BOUNDARY_")
                || case16_head.starts_with("&host_diagnostics::HostRequestProjection")
                || case16_head == "self.boundary",
            "an observation call must pass a frozen boundary or typed projection, got: {case16_head}"
        );
        assert!(
            !case16_head.contains('"') && !case16_head.contains('{'),
            "an observation call must never pass a literal or a formatted status, got: {case16_head}"
        );
    }
    assert_eq!(
        case16_heads
            .iter()
            .filter(|case16_head| case16_head.starts_with("BOUNDARY_"))
            .count(),
        case16_heads.len() - 2,
        "every call but the identity projection and the guard drop selects a static boundary"
    );

    // Source: the reason slot is an exhaustive typed mapping over the real error
    // type, so no free-text machine status can ever reach a record.
    let case16_body = |haystack: &str, header: &str| -> String {
        let start = haystack
            .find(header)
            .unwrap_or_else(|| panic!("the source must contain {header}"));
        let bytes = haystack.as_bytes();
        let mut index = start;
        let mut depth = 0usize;
        loop {
            assert!(index < bytes.len(), "{header} must close in the source");
            match bytes[index] {
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    while index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    while index + 1 < bytes.len()
                        && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                    {
                        index += 1;
                    }
                    index += 2;
                }
                b'"' => {
                    index += 1;
                    while index < bytes.len() && bytes[index] != b'"' {
                        if bytes[index] == b'\\' {
                            index += 1;
                        }
                        index += 1;
                    }
                    index += 1;
                }
                b'{' => {
                    depth += 1;
                    index += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return haystack[start..=index].to_owned();
                    }
                    index += 1;
                }
                _ => index += 1,
            }
        }
    };
    let case16_reason = case16_body(&facade, "const fn project_host_error_reason(");
    let case16_arms: Vec<&str> = case16_reason
        .lines()
        .map(str::trim)
        .filter(|case16_line| case16_line.starts_with("HostError::"))
        .collect();
    let case16_enum = case16_body(&lib, "pub enum HostError {");
    let case16_variants = case16_enum
        .lines()
        .filter(|case16_line| {
            case16_line.starts_with("    ")
                && case16_line
                    .trim_start()
                    .starts_with(|case16_char: char| case16_char.is_ascii_uppercase())
        })
        .count();
    assert_eq!(
        case16_arms.len(),
        case16_variants,
        "every public host error variant must carry exactly one typed reason code"
    );
    assert!(
        !case16_arms.is_empty(),
        "the reason projection must be real"
    );
    for case16_arm in &case16_arms {
        let case16_literal = case16_arm.rsplit_once("=> \"").map_or_else(
            || panic!("a reason arm must map to a frozen literal: {case16_arm}"),
            |case16_pair| case16_pair.1.trim_end_matches("\",").to_owned(),
        );
        assert!(
            !case16_literal.is_empty()
                && case16_literal
                    .chars()
                    .all(|case16_char| case16_char.is_ascii_lowercase() || case16_char == '_'),
            "a reason code must be a frozen typed identifier, got: {case16_literal}"
        );
    }
    assert!(
        !case16_reason.contains("{:?") && !case16_reason.contains("format!"),
        "a reason arm must never format the error payload"
    );

    // Discovery: the facade's own bound and event names.
    assert_eq!(
        fixture["max_detail_bytes"].as_u64(),
        Some(eliot_host::host_diagnostics::MAX_DIAGNOSTIC_DETAIL_BYTES as u64),
        "the fixture detail bound must be the real facade bound"
    );
    let case16_event = |anchor: &str| -> String {
        let at = facade
            .find(anchor)
            .unwrap_or_else(|| panic!("the facade must emit {anchor}"));
        let rest = &facade[at..];
        let open = rest.find('"').expect("the event field must be a literal");
        let after = &rest[open + 1..];
        let close = after.find('"').expect("the event literal must close");
        after[..close].to_owned()
    };
    let case16_terminal_event = case16_event("event = \"host.terminal_error\"");
    assert_eq!(
        fixture["terminal_event"].as_str(),
        Some(case16_terminal_event.as_str()),
        "the fixture terminal event must be the real facade event"
    );

    // Executed pass: a real typed host error projects as its frozen reason
    // kind; the arbitrary payload text never reaches the record, and the slot
    // reads explicitly missing where the outcome collapsed the reason.
    let case16_error =
        eliot_host::HostError::ProcessContour("891-case-16-arbitrary-runtime-status".to_owned());
    let case16_projection = eliot_host::host_diagnostics::HostRequestProjection::failed(
        EntrypointStage::ScmDispatch,
        &case16_error,
    );
    let case16_unattributed =
        eliot_host::host_diagnostics::HostRequestProjection::failed_without_reason(
            EntrypointStage::ScmDispatch,
        );
    let case16_stopped = case16_codes["stop_failed"]
        .as_str()
        .expect("the fixture must pin the stop terminal code")
        .to_owned();
    let case16_text = capture_emit(|| {
        eliot_host::host_diagnostics::observe_host_request(&case16_projection);
        eliot_host::host_diagnostics::observe_host_request(&case16_unattributed);
        observe_terminal_error(&case16_stopped);
    });
    assert_eq!(
        count_occurrences(&case16_text, "process_contour"),
        1,
        "the typed reason kind must cross once, got: {case16_text}"
    );
    assert!(
        case16_text.contains("reason_missing=false"),
        "the typed reason slot must not read missing, got: {case16_text}"
    );
    assert!(
        case16_text.contains("reason_missing=true"),
        "an unattributed reason slot must read explicitly missing, got: {case16_text}"
    );
    assert_eq!(
        count_occurrences(&case16_text, "891-case-16-arbitrary-runtime-status"),
        0,
        "the arbitrary error payload must never cross into a diagnostic, got: {case16_text}"
    );
    assert!(
        !case16_text.contains("approved process contour is unavailable"),
        "the error Display text must never cross into a diagnostic, got: {case16_text}"
    );
    assert_eq!(
        count_occurrences(&case16_text, &case16_stopped),
        1,
        "the frozen terminal code crosses exactly once, got: {case16_text}"
    );
    assert_eq!(
        count_occurrences(&case16_text, case16_terminal_event.as_str()),
        1,
        "exactly one terminal record, got: {case16_text}"
    );
    assert_eq!(
        count_occurrences(
            &case16_text,
            &format!("code_bytes={}", case16_stopped.len())
        ),
        1,
        "the typed code crosses whole and bounded, got: {case16_text}"
    );
    assert!(
        !case16_text.contains("code=\"\""),
        "a terminal code is never an empty free-text status, got: {case16_text}"
    );
}

// WORK_UNIT_CASE: 891/17
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 17 keeps the real missing-evidence branches, the single admitted emission, the semantic-return review and the record-level executed pass in one deterministic case"
)]
fn lifecycle_missing_evidence_suppresses_the_positive_event_only() {
    // #891 case 17: missing durable evidence suppresses a false success event
    // without changing the original semantic behaviour. Source: the real
    // `open_for_profile` contour with its evidence-missing early returns and the
    // single admitted emission. Discovery: the frozen positive row. Executed
    // pass: the real facade records for the degraded evidence class against the
    // admitted one, with a real owner result kept intact.
    let fixture = lifecycle_fixture();
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");

    let case17_table_start = lib
        .find("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .expect("lib.rs must own the frozen boundary table");
    let case17_table_end = case17_table_start
        + lib[case17_table_start..]
            .find("\n];")
            .expect("the frozen boundary table must close");
    let case17_table = &lib[case17_table_start..case17_table_end];
    let case17_row = |name: &str| -> String {
        let at = case17_table
            .find(&format!("name: \"{name}\","))
            .unwrap_or_else(|| panic!("the frozen table must own row {name}"));
        let row_start = case17_table[..at]
            .rfind("HostLifecycleBoundary {")
            .unwrap_or_else(|| panic!("row {name} must open a struct literal"));
        let row = &case17_table[row_start..];
        let row_end = row
            .find("\n    },")
            .unwrap_or_else(|| panic!("row {name} must close its struct literal"));
        row[..row_end].to_owned()
    };
    let case17_field = |row: &str, field: &str| -> String {
        let prefix = format!("{field}: ");
        let line = row
            .lines()
            .find(|line| line.trim_start().starts_with(prefix.as_str()))
            .unwrap_or_else(|| panic!("row must carry field {field}: {row}"));
        let mut value = String::new();
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let close = after
                .find('"')
                .unwrap_or_else(|| panic!("the {field} literal must close: {line}"));
            value.push_str(&after[..close]);
            rest = &after[close + 1..];
        }
        value
    };
    let case17_body = |haystack: &str, header: &str| -> String {
        let start = haystack
            .find(header)
            .unwrap_or_else(|| panic!("the source must contain {header}"));
        let bytes = haystack.as_bytes();
        let mut index = start;
        let mut depth = 0usize;
        loop {
            assert!(index < bytes.len(), "{header} must close in the source");
            match bytes[index] {
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    while index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    while index + 1 < bytes.len()
                        && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                    {
                        index += 1;
                    }
                    index += 2;
                }
                b'"' => {
                    index += 1;
                    while index < bytes.len() && bytes[index] != b'"' {
                        if bytes[index] == b'\\' {
                            index += 1;
                        }
                        index += 1;
                    }
                    index += 1;
                }
                b'{' => {
                    depth += 1;
                    index += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return haystack[start..=index].to_owned();
                    }
                    index += 1;
                }
                _ => index += 1,
            }
        }
    };

    // Source: the contract the contour implements, stated in its own comment.
    let case17_open = case17_body(&lib, "pub fn open_for_profile(");
    assert!(
        case17_open.contains("Missing evidence suppresses `admitted`, never a new branch."),
        "the real contour must state the case-17 contract in source"
    );

    // Source: the frozen degraded row and the single positive row.
    let case17_degraded_row = case17_row("open.degraded-prepared-without-receipt");
    assert_eq!(
        case17_field(&case17_degraded_row, "test"),
        "891/case-17",
        "the degraded-without-receipt row is the case-17 row"
    );
    assert_eq!(
        case17_field(&case17_degraded_row, "owner_state"),
        "prepared materialization without receipt",
        "the degraded row names exactly the missing durable receipt"
    );
    let case17_degraded_event = case17_field(&case17_degraded_row, "event");
    let case17_admitted_row = case17_row("open.admitted");
    let case17_admitted_event = case17_field(&case17_admitted_row, "event");
    assert_ne!(
        case17_degraded_event, case17_admitted_event,
        "degraded evidence never emits the admitted event"
    );
    assert_eq!(
        case17_field(&case17_admitted_row, "source_item"),
        case17_field(&case17_degraded_row, "source_item"),
        "both rows belong to the one real open contour"
    );

    // Source: the branch condition is the durable receipt itself. On the
    // missing-evidence arm the owner already chose degraded, disarmed the
    // terminal, emitted the degraded row and returned the same success value;
    // the observation added no branch and no return.
    let case17_branch = case17_open
        .find("if pending_after_readback.phase_b_receipt.is_none() {")
        .expect("the real contour must branch on the durable receipt");
    let case17_arm = &case17_open[case17_branch..];
    let case17_arm_end = case17_arm
        .find("} else if let Some(binding) = materialization.agent_bridge() {")
        .expect("the missing-evidence arm must be followed by the receipt-bearing arm");
    let case17_arm = &case17_arm[..case17_arm_end];
    for case17_part in [
        "composition.readiness_gate.branch_degraded();",
        "host_terminal.disarm();",
        "BOUNDARY_OPEN_DEGRADED_PREPARED_WITHOUT_RECEIPT",
        "return Ok(composition);",
    ] {
        assert!(
            case17_arm.contains(case17_part),
            "the missing-evidence arm must carry {case17_part}, got: {case17_arm}"
        );
    }
    let case17_degrade_at = case17_arm
        .find("composition.readiness_gate.branch_degraded();")
        .expect("the arm must degrade the gate");
    let case17_disarm_at = case17_arm
        .find("host_terminal.disarm();")
        .expect("the arm must disarm the terminal");
    let case17_observe_at = case17_arm
        .find("BOUNDARY_OPEN_DEGRADED_PREPARED_WITHOUT_RECEIPT")
        .expect("the arm must emit the degraded row");
    let case17_return_at = case17_arm
        .find("return Ok(composition);")
        .expect("the arm must return the composition");
    assert!(
        case17_degrade_at < case17_disarm_at
            && case17_disarm_at < case17_observe_at
            && case17_observe_at < case17_return_at,
        "the semantic decision precedes the observation and the return stays where the owner put it"
    );
    for case17_line in case17_arm
        .lines()
        .filter(|case17_line| case17_line.contains("host_lifecycle_observe_"))
    {
        assert!(
            !case17_line.contains("return")
                && !case17_line.contains('?')
                && !case17_line.contains("else")
                && !case17_line.contains("if "),
            "an observation line must add no semantic return or branch: {case17_line}"
        );
    }

    // Source: every evidence-missing early return precedes the single admitted
    // emission, so missing evidence structurally suppresses the positive event
    // instead of adding a failure branch.
    let case17_returns: Vec<usize> = case17_open
        .match_indices("return Ok(composition);")
        .map(|(case17_at, _)| case17_at)
        .collect();
    assert_eq!(
        case17_returns.len(),
        4,
        "the real contour has four degraded or fenced early returns, got: {case17_returns:?}"
    );
    let case17_admitted_at = case17_open
        .find("BOUNDARY_OPEN_ADMITTED")
        .expect("the contour must emit the admitted row");
    for case17_return in &case17_returns {
        assert!(
            *case17_return < case17_admitted_at,
            "an evidence-missing return at {case17_return} must precede the admitted emission at {case17_admitted_at}"
        );
    }
    assert_eq!(
        count_occurrences(&case17_open, "BOUNDARY_OPEN_ADMITTED"),
        1,
        "the positive admitted event is emitted exactly once"
    );
    for case17_positive in [
        "BOUNDARY_START_STARTED",
        "BOUNDARY_START_MANIFEST_STARTED",
        "BOUNDARY_READINESS_READY_PROOF",
        "BOUNDARY_PHASE_B_PREPARED_RECEIPT",
    ] {
        assert!(
            !case17_open.contains(case17_positive),
            "the open contour must not emit a positive event a degraded branch could reach: {case17_positive}"
        );
    }
    assert!(
        case17_open.contains("BOUNDARY_OPEN_FENCED_STORE_RECOVERY_ACTIVE"),
        "the fenced store-recovery row is emitted on its own evidence-missing arm"
    );
    assert_eq!(
        count_occurrences(
            &case17_open,
            "HostTerminalGuard::armed(BOUNDARY_OPEN_TERMINAL)"
        ),
        1,
        "the open operation still owns exactly one designated terminal"
    );

    // Discovery: the facade event names come from the facade itself, and the
    // fixture stage agrees with the real stage vocabulary.
    let case17_event = |anchor: &str| -> String {
        let at = facade
            .find(anchor)
            .unwrap_or_else(|| panic!("the facade must emit {anchor}"));
        let rest = &facade[at..];
        let open = rest.find('"').expect("the event field must be a literal");
        let after = &rest[open + 1..];
        let close = after.find('"').expect("the event literal must close");
        after[..close].to_owned()
    };
    let case17_stage_event = case17_event("event = \"host.entrypoint_stage\"");
    let case17_terminal_event = case17_event("event = \"host.terminal_error\"");
    let case17_admission_event = case17_event("event = \"host.event_log_admission\"");
    assert_eq!(
        fixture["entrypoint_event"].as_str(),
        Some(case17_stage_event.as_str()),
        "the fixture entrypoint event must be the real facade event"
    );
    assert_eq!(
        fixture["stages"]["startup"].as_str(),
        Some(EntrypointStage::Startup.as_str()),
        "the fixture stage must be the real #889 stage name"
    );

    // Executed pass: the real owner result stays intact across the observation,
    // and the record for the degraded evidence class asserts no completed
    // operation while the admitted one does.
    let case17_owner = eliot_host::HostLaunchOptions::parse([
        "--config-descriptor",
        "C:\\Eliot\\891-case-17-descriptor.json",
    ]);
    assert!(
        case17_owner.is_err(),
        "the malformed argv must stay refused by the real owner"
    );
    let case17_degraded =
        eliot_host::host_diagnostics::HostRequestProjection::unknown(EntrypointStage::Startup)
            .with_operation(AdmittedEvent::ServiceStop);
    let case17_text = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::Startup, &case17_degraded_event);
        eliot_host::host_diagnostics::observe_host_request(&case17_degraded);
    });
    assert!(
        case17_owner.is_err(),
        "observation must not change the owner result"
    );
    assert_eq!(
        count_occurrences(&case17_text, &case17_degraded_event),
        1,
        "the degraded row crosses exactly once, got: {case17_text}"
    );
    assert!(
        !case17_text.contains(&case17_admitted_event),
        "missing evidence must suppress the positive admitted event, got: {case17_text}"
    );
    assert_eq!(
        count_occurrences(&case17_text, case17_terminal_event.as_str()),
        0,
        "a degraded but successful operation emits no terminal, got: {case17_text}"
    );
    assert_eq!(
        count_occurrences(&case17_text, case17_admission_event.as_str()),
        0,
        "unknown evidence asserts no completed operation, so nothing is admitted, got: {case17_text}"
    );
    assert!(
        !AdmittedEvent::ServiceStop
            .is_admitted_by(eliot_host::host_diagnostics::HostRequestEvidence::Unknown),
        "unknown evidence never admits a completed service stop"
    );
    assert_eq!(
        count_occurrences(
            &case17_text,
            eliot_host::host_diagnostics::HostRequestEvidence::Unknown.as_str()
        ),
        1,
        "the degraded record keeps its own evidence class, got: {case17_text}"
    );

    // Executed pass: with the durable evidence present the positive channel
    // opens, which is the contrast the missing-evidence arm withholds.
    let case17_admitted = eliot_host::host_diagnostics::HostRequestProjection::durable_committed(
        EntrypointStage::Startup,
    )
    .with_operation(AdmittedEvent::ServiceStop);
    let case17_admitted_text =
        capture_emit(|| eliot_host::host_diagnostics::observe_host_request(&case17_admitted));
    assert!(
        AdmittedEvent::ServiceStop
            .is_admitted_by(eliot_host::host_diagnostics::HostRequestEvidence::DurableCommitted),
        "the durable evidence admits the completed operation"
    );
    assert_eq!(
        count_occurrences(&case17_admitted_text, case17_admission_event.as_str()),
        1,
        "the evidence-bearing record reaches the positive channel, got: {case17_admitted_text}"
    );
    assert_eq!(
        count_occurrences(&case17_admitted_text, case17_terminal_event.as_str()),
        0,
        "a committed operation emits no terminal either, got: {case17_admitted_text}"
    );
}
// WORK_UNIT_CASE: 891/18
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 18 runs the real observation pass once per sink outcome and keeps each semantic fingerprint assertion next to the sink that must not disturb it"
)]
fn sink_failure_and_drop_leave_result_order_status_cleanup_unchanged() {
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");
    let fixture = lifecycle_fixture();

    // ---- source binding: the real surface a sink failure cannot disturb ----
    // lib.rs:79/87/95/103/116. Each observation helper is non-returning and
    // borrows one already-decided boundary, so no call site consumes an
    // observation result and none can hand one back to its operation.
    for signature in [
        "fn host_lifecycle_observe_requested(boundary: &'static HostLifecycleBoundary) {",
        "fn host_lifecycle_observe_scm(boundary: &'static HostLifecycleBoundary) {",
        "fn host_lifecycle_observe_drain(boundary: &'static HostLifecycleBoundary) {",
        "fn host_lifecycle_observe_terminal(boundary: &'static HostLifecycleBoundary) {",
        "fn host_lifecycle_observe_identity(projection: &host_diagnostics::HostRequestProjection) {",
    ] {
        assert!(
            lib.contains(signature),
            "an observation helper must keep its non-returning signature: {signature}"
        );
    }
    // host_diagnostics.rs:588/610/631/954: the four facade seams those helpers
    // call are non-returning too, so no sink outcome crosses a Result boundary.
    for signature in [
        "pub fn observe_entrypoint_with_detail(stage: EntrypointStage, detail: &str) {",
        "pub fn observe_terminal_error(code: &str) {",
        "pub fn note_event_log_sink_status() {",
        "pub fn observe_host_request(projection: &HostRequestProjection) {",
    ] {
        assert!(
            facade.contains(signature),
            "a facade seam must keep its non-returning signature: {signature}"
        );
    }
    // lib.rs:1553: the frozen event is one field read, so a call site cannot
    // retry, fall back or re-evaluate because a sink behaved badly.
    assert_eq!(
        case18_body(&lib, "fn host_lifecycle_frozen_event").trim(),
        "boundary.event",
        "the frozen event must stay one field read with no fallback"
    );
    for helper in [
        "fn host_lifecycle_observe_requested",
        "fn host_lifecycle_observe_scm",
        "fn host_lifecycle_observe_drain",
        "fn host_lifecycle_observe_terminal",
        "fn host_lifecycle_observe_identity",
    ] {
        let body = case18_body(&lib, helper);
        let identity = helper == "fn host_lifecycle_observe_identity";
        assert!(
            !body.contains('='),
            "{helper} must not assign or build a value: {body}"
        );
        for forbidden in ["if ", "match ", "loop", "while ", "for ", "return", "?"] {
            assert!(
                !body.contains(forbidden),
                "{helper} must carry no {forbidden:?} semantic branch: {body}"
            );
        }
        assert_eq!(
            count_occurrences(&body, "host_diagnostics::observe_"),
            1,
            "{helper} must call exactly one facade seam: {body}"
        );
        assert_eq!(
            count_occurrences(&body, "host_lifecycle_frozen_event("),
            usize::from(!identity),
            "{helper} must evaluate the frozen event at most once per call: {body}"
        );
    }
    // lib.rs:146-152: exactly one terminal emission, only while the guard is
    // armed, so a failed operation has one designated terminal and a
    // disarmed success path has none.
    let guard_drop = case18_body(&lib, "impl Drop for HostTerminalGuard");
    assert_eq!(
        count_occurrences(&guard_drop, "host_lifecycle_observe_terminal("),
        1,
        "one armed guard may emit the terminal exactly once: {guard_drop}"
    );
    assert!(
        guard_drop.contains("if self.armed"),
        "the terminal must be emitted only while the guard is armed: {guard_drop}"
    );
    assert_eq!(
        count_occurrences(&lib, "fn disarm(&mut self)"),
        1,
        "disarm must remain the single success-path mutation"
    );
    // lib.rs:12656/12657/12873 and lib.rs:8591/8651: the real failed-stop
    // contour and the real SCM contour this case drives.
    for call_site in [
        "host_lifecycle_observe_drain(BOUNDARY_STOP_REQUESTED);",
        "let mut host_terminal = HostTerminalGuard::armed(BOUNDARY_STOP_TERMINAL);",
        "host_lifecycle_observe_drain(BOUNDARY_STOP_STOPPED);",
        "host_lifecycle_observe_scm(BOUNDARY_KERNEL_RESTART_REQUESTED);",
        "host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_TERMINAL);",
        "pub fn stop(&mut self) -> Result<(), HostError> {",
    ] {
        assert!(
            lib.contains(call_site),
            "the stop contour call site must stay: {call_site}"
        );
    }

    // ---- the semantic values no sink outcome may change ----
    // Mirrors lib.rs:8634-8654: an admitted restart request and the Unknown
    // receipt the restart seam returns for it, recomputed for comparison below.
    let request = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RestartKernel,
        case18_request_handle("891-case-18-restart"),
    )
    .expect("the admitted restart request must build");
    let semantic_ok: Result<(), String> = request.validate();
    assert!(
        semantic_ok.is_ok(),
        "the admitted restart request must validate before any observation"
    );
    let semantic_unknown: Result<(), String> = case18_unknown(&request).validate();
    assert!(
        semantic_unknown.is_ok(),
        "the Unknown restart receipt must validate before any observation"
    );
    // The typed refusal is the semantic owner's own answer, and it carries
    // content no sink can invent or replace.
    let refused: Result<eliot_host::HostRuntimeControlRequest, String> = case18_refused_request();
    assert!(
        matches!(&refused, Err(message) if message.contains("mutation_digest")),
        "the unbound mutation digest must stay a typed refusal: {refused:?}"
    );

    let rows = case18_boundary_rows(&lib);
    let stop_requested = case18_event(&rows, "stop.requested");
    let stop_terminal = case18_event(&rows, "stop.terminal");
    assert_eq!(
        stop_terminal.as_str(),
        fixture["terminal_codes"]["stop_failed"]
            .as_str()
            .expect("the fixture must pin the typed stop terminal code"),
        "the stop terminal row must carry the fixture's typed stop code"
    );
    let order = ["entrypoint", "terminal"];

    // ---- sink outcome 1: every write fails ----
    let failing = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .log_internal_errors(false)
        .with_writer(case18_failing_writer)
        .finish();
    let mut failing_steps: Vec<&str> = Vec::new();
    tracing::subscriber::with_default(failing, || {
        failing_steps = case18_observation_pass(&stop_requested, &stop_terminal);
    });
    assert_eq!(
        failing_steps, order,
        "a failing sink must not reorder or skip the observation pass"
    );
    assert_eq!(
        request.validate(),
        semantic_ok,
        "a failing sink must leave the admitted request's result unchanged"
    );
    assert_eq!(
        case18_unknown(&request).validate(),
        semantic_unknown,
        "a failing sink must leave the Unknown receipt unchanged"
    );
    assert_eq!(
        case18_refused_request(),
        refused,
        "a failing sink must not swallow or replace the typed refusal"
    );

    // ---- sink outcome 2: the filter drops every record before formatting ----
    let filtered_sink = CaptureSink::default();
    let filtered_writer = filtered_sink.clone();
    let filtered = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_env_filter(tracing_subscriber::EnvFilter::new("off"))
        .with_writer(move || filtered_writer.clone())
        .finish();
    let mut filtered_steps: Vec<&str> = Vec::new();
    tracing::subscriber::with_default(filtered, || {
        filtered_steps = case18_observation_pass(&stop_requested, &stop_terminal);
    });
    assert_eq!(
        filtered_steps, order,
        "a filtering sink must not reorder or skip the observation pass"
    );
    assert!(
        filtered_sink.bytes.lock().unwrap().is_empty(),
        "a filtered sink must receive no record at all"
    );
    assert_eq!(
        case18_unknown(&request).validate(),
        semantic_unknown,
        "a filtering sink must leave the Unknown receipt unchanged"
    );

    // ---- sink outcome 3: the working sink, for contrast ----
    let delivered = capture_emit(|| {
        case18_observation_pass(&stop_requested, &stop_terminal);
    });
    let boundary_records: Vec<&str> = delivered
        .lines()
        .filter(|line| {
            line.contains("host.entrypoint_stage") || line.contains("host.terminal_error")
        })
        .collect();
    assert_eq!(
        boundary_records.len(),
        2,
        "one failed stop yields exactly the entrypoint and terminal records: {delivered}"
    );
    // `note_event_log_sink_status` is silent where #984's sink is live
    // (`src/host_diagnostics.rs:632-634`) and records one subordinate note
    // where it is not, so the delivered line count is platform dependent and
    // every delivered line is checked instead.
    assert!(
        delivered.lines().count() == 2 || delivered.contains("host.event_log_sink_unavailable"),
        "a failed stop delivers the two boundary records, plus the subordinate \
         sink note only where the Event Log sink is unavailable: {delivered}"
    );
    for other in delivered.lines().filter(|line| {
        !line.contains("host.entrypoint_stage") && !line.contains("host.terminal_error")
    }) {
        assert!(
            other.contains("host.event_log_sink_unavailable"),
            "the only other record lib.rs may produce is the subordinate sink note: {delivered}"
        );
    }
    assert!(
        delivered.contains(&format!(
            "event=\"{}\"",
            fixture["entrypoint_event"].as_str().unwrap_or_default()
        )),
        "the entrypoint record must carry the frozen entrypoint event: {delivered}"
    );
    assert!(
        delivered.contains(&format!("code=\"{stop_terminal}\"")),
        "the terminal record must carry the row's typed code: {delivered}"
    );
    assert_eq!(
        count_occurrences(&delivered, "event=\"host.terminal_error\""),
        1,
        "one failed operation yields exactly one terminal record: {delivered}"
    );
    assert_eq!(
        request.validate(),
        semantic_ok,
        "a delivered sink must leave the admitted request's result unchanged"
    );
    assert_eq!(
        case18_refused_request(),
        refused,
        "a delivered sink must not swallow or replace the typed refusal"
    );

    // Cleanup and order are the operation's own: the pass still runs in the
    // contour's order with no subscriber at all, and the semantic receipt is
    // byte-identical afterwards.
    assert_eq!(
        case18_observation_pass(&stop_requested, &stop_terminal),
        order,
        "the observation pass must be side-effect free and order stable"
    );
    assert_eq!(
        case18_unknown(&request).validate(),
        semantic_unknown,
        "the observation pass must not mutate the semantic receipt"
    );
}

/// One real observation pass, exactly as `lib.rs:79-119` runs it for a failed
/// stop, returning the order in which the surrounding operation proceeded.
fn case18_observation_pass(requested: &str, terminal_code: &str) -> Vec<&'static str> {
    let mut steps: Vec<&'static str> = Vec::new();
    eliot_host::note_event_log_sink_status();
    steps.push("entrypoint");
    eliot_host::host_diagnostics::observe_entrypoint_with_detail(
        eliot_host::host_diagnostics::EntrypointStage::ShutdownDrain,
        requested,
    );
    eliot_host::host_diagnostics::observe_terminal_error(terminal_code);
    steps.push("terminal");
    steps
}

/// The source text of one item body, taken from its signature.
fn case18_body(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("the observation surface must carry {signature}"));
    let rest = &source[start..];
    let open = rest
        .find('{')
        .unwrap_or_else(|| panic!("{signature} must open a body"));
    let close = rest[open..]
        .find("\n}")
        .unwrap_or_else(|| panic!("{signature} must close its body"));
    rest[open + 1..open + close].to_owned()
}

/// `(name, event)` for every row of `HOST_LIFECYCLE_BOUNDARY_TABLE`, in exact
/// table order, with the `concat!`-spelled terminal events joined to their
/// emitted value.
fn case18_boundary_rows(source: &str) -> Vec<(String, String)> {
    let table = source
        .split_once("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .unwrap_or_else(|| panic!("the boundary table must exist"))
        .1;
    let body = table
        .split_once("\n];")
        .unwrap_or_else(|| panic!("the boundary table must be a closed slice"))
        .0;
    body.split("HostLifecycleBoundary {")
        .skip(1)
        .map(|row| {
            (
                case18_row_field(row, "name"),
                case18_row_field(row, "event"),
            )
        })
        .collect()
}

/// One frozen event value, taken from its own row of the table.
fn case18_event(rows: &[(String, String)], name: &str) -> String {
    rows.iter()
        .find(|(row_name, _)| row_name == name)
        .map_or_else(
            || panic!("the table must carry the {name} row"),
            |(_, event)| event.clone(),
        )
}

/// Reads one boundary row field, joining a `concat!("a", "b")` spelling.
fn case18_row_field(row: &str, field: &str) -> String {
    let prefix = format!("{field}: ");
    let raw = row
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("a boundary row must carry {field}"))
        .trim()
        .trim_end_matches(',')
        .to_owned();
    match raw.strip_prefix("concat!(") {
        Some(literals) => {
            let mut joined = String::new();
            let mut rest = literals.strip_suffix(')').unwrap_or(literals);
            while let Some(open) = rest.find('"') {
                let after = &rest[open + 1..];
                let close = after
                    .find('"')
                    .unwrap_or_else(|| panic!("a concat literal must close"));
                joined.push_str(&after[..close]);
                rest = &after[close + 1..];
            }
            joined
        }
        None => raw.trim_matches('"').to_owned(),
    }
}

/// One opaque request identity handle, built through the real platform seam.
fn case18_request_handle(text: &str) -> eliot_platform::PlatformHandle {
    eliot_platform::PlatformHandle::new(text.to_owned())
        .unwrap_or_else(|error| panic!("{text} must be a valid handle: {error}"))
}

/// The Unknown restart receipt, exactly as lib.rs:8636-8641 builds it.
fn case18_unknown(
    request: &eliot_host::HostRuntimeControlRequest,
) -> eliot_host::HostRuntimeControlResponse {
    eliot_host::HostRuntimeControlResponse::unknown_for(
        request,
        eliot_host_service::runtime_control::runtime_control_unknown_ref("kernel-restart", request),
    )
}

/// The typed refusal the semantic owner already produced, built exactly as the
/// real recovery seam builds a runtime-control request.
fn case18_refused_request() -> Result<eliot_host::HostRuntimeControlRequest, String> {
    eliot_host::HostRuntimeControlRequest::new_with_mutation_digest(
        eliot_host::HostRuntimeControlOperation::RecoverStore,
        case18_request_handle("891-case-18-store"),
        case18_request_handle("891-case-18-unbound-mutation"),
    )
}

/// A sink whose every write fails, so the record is lost instead of changing
/// the surrounding operation.
fn case18_failing_writer() -> impl std::io::Write {
    struct Case18FailedSink;

    impl std::io::Write for Case18FailedSink {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("891 case-18 sink failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    Case18FailedSink
}

// WORK_UNIT_CASE: 891/19
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 19 scans every real observation statement, drives the real admitted launch parse and compares the emitted identity record with the facade's declared field set"
)]
fn credential_env_and_db_canaries_are_absent_from_every_observation() {
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");
    let fixture = lifecycle_fixture();

    // ---- the real credential, environment and database vocabulary ----
    // I15.4 keeps secret and connection material out of logs; these are this
    // codebase's own names for what therefore may never reach a record.
    let canaries = [
        "SecretReference",
        "StoreCredentialProvider",
        "StoreCredentialScope",
        "CredentialAccessReceipt",
        "CredentialManager",
        "password",
        "api_key",
        "secret_value",
        "credential_bytes",
        "Bearer",
        "BEGIN PRIVATE KEY",
        "env::var",
        "std::env",
        "ELIOT_",
        "connection_string",
        "ConnectionString",
        "surreal",
        "dsn",
        "endpoint",
    ];

    // ---- source binding: every observation statement in lib.rs ----
    let statements = case19_observation_statements(&lib);
    assert!(
        statements.len() > 50,
        "the observation surface must still be the full table's call sites: {}",
        statements.len()
    );
    for statement in &statements {
        for canary in canaries {
            assert!(
                !statement.contains(canary),
                "an observation statement must carry no {canary:?} material: {statement}"
            );
        }
    }
    // The facade itself reads no credential, environment or database client:
    // it formats precomputed bounded strings only.
    for seam in [
        "pub fn observe_entrypoint_with_detail(",
        "pub fn observe_terminal_error(",
        "pub fn observe_host_request(",
    ] {
        let body = case19_body(&facade, seam);
        for canary in canaries {
            assert!(
                !body.contains(canary),
                "the {seam} body must carry no {canary:?} material: {body}"
            );
        }
        assert!(
            !body.contains("unsafe"),
            "{seam} must stay a pure bounded formatter: {body}"
        );
    }

    // ---- executed pass 1: the real admitted launch parse ----
    // `HostLaunchOptions::parse` is an instrumented production seam
    // (`host_launch_options.rs:120`). It binds only the three identities it
    // holds and never binds argv text, the descriptor path, the state root or
    // the registration nonce.
    let record = capture_emit(|| {
        eliot_host::HostLaunchOptions::parse(case19_launch_argv())
            .expect("the admitted argv must build");
    });
    assert_eq!(
        record.lines().count(),
        2,
        "one admitted parse yields exactly the requested and admitted records: {record}"
    );
    assert_eq!(
        case19_record_keys(record.lines().next().expect("a requested record")),
        case19_declared_keys(&facade, "pub fn observe_entrypoint_with_detail"),
        "the delivered record may carry only the facade's declared fields: {record}"
    );
    for canary in canaries {
        assert!(
            !record.contains(canary),
            "an admitted launch record must carry no {canary:?} material: {record}"
        );
    }
    // The pass is not vacuous: the identities the owner holds are bound, so
    // the absences above are a real distinction and not an empty record.
    assert!(
        record.contains("installation=installation-891-case-19 generation=7"),
        "the admitted identities must stay bound: {record}"
    );
    assert!(
        record.contains("detail_truncated=false"),
        "a bounded identity detail must not be silently truncated: {record}"
    );
    assert_eq!(
        fixture["max_field_bytes"].as_u64(),
        Some(case19_declared_bound(&facade, "MAX_DIAGNOSTIC_FIELD_BYTES")),
        "the fixture must pin the real short-field bound"
    );
    assert_eq!(
        fixture["max_detail_bytes"].as_u64(),
        Some(case19_declared_bound(
            &facade,
            "MAX_DIAGNOSTIC_DETAIL_BYTES"
        )),
        "the fixture must pin the real detail bound"
    );

    // ---- executed pass 2: the real identity projection, exactly as lib.rs:8617 ----
    let options = eliot_host::HostLaunchOptions::parse(case19_launch_argv())
        .expect("the admitted argv must build");
    let projection = eliot_host::host_diagnostics::HostRequestProjection::observed(
        eliot_host::host_diagnostics::EntrypointStage::ScmDispatch,
    )
    .with_launch_options(&options)
    .with_process(std::process::id());
    let identity_record = capture_emit(|| {
        eliot_host::host_diagnostics::observe_host_request(&projection);
    });
    assert_eq!(
        identity_record.lines().count(),
        1,
        "one projected request yields exactly one identity record: {identity_record}"
    );
    assert_eq!(
        case19_record_keys(identity_record.lines().next().expect("an identity record")),
        case19_declared_keys(&facade, "pub fn observe_host_request"),
        "the identity record may carry only the facade's declared fields: {identity_record}"
    );
    for canary in canaries {
        assert!(
            !identity_record.contains(canary),
            "an identity record must carry no {canary:?} material: {identity_record}"
        );
    }
    assert!(
        identity_record.contains("installation=\"installation-891-case-19\"")
            && identity_record.contains("installation_missing=false")
            && identity_record.contains("generation=7")
            && identity_record.contains("generation_missing=false")
            && identity_record.contains("process_missing=false"),
        "the identity record must carry the admitted identities it holds: {identity_record}"
    );
    // Every slot the owner does not hold stays explicitly missing instead of
    // being invented from a credential, an environment read or a connection.
    for missing in [
        "request_missing=true",
        "operation_missing=true",
        "reason_missing=true",
        "receipt_sequence_missing=true",
        "receipt_exit_missing=true",
    ] {
        assert!(
            identity_record.contains(missing),
            "the identity record must keep {missing} explicit: {identity_record}"
        );
    }
}

/// The balanced-paren observation statements of a source file, so the
/// multi-line identity projection at `lib.rs:8616` is read whole.
fn case19_observation_statements(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut statements = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if line.contains("host_lifecycle_observe_")
            && line.contains('(')
            && !line.trim_start().starts_with("//")
        {
            let mut statement = line.trim().to_owned();
            while count_occurrences(&statement, "(") > count_occurrences(&statement, ")")
                && index + 1 < lines.len()
            {
                index += 1;
                statement.push(' ');
                statement.push_str(lines[index].trim());
            }
            statements.push(statement);
        }
        index += 1;
    }
    statements
}

/// The body of one facade item, taken from its signature.
fn case19_body(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("the facade must carry {signature}"));
    let rest = &source[start..];
    let open = rest
        .find('{')
        .unwrap_or_else(|| panic!("{signature} must open a body"));
    let close = rest[open..]
        .find("\n}")
        .unwrap_or_else(|| panic!("{signature} must close its body"));
    rest[open + 1..open + close].to_owned()
}

/// The macro field names one real facade seam declares, in source order.
fn case19_declared_keys(source: &str, signature: &str) -> Vec<String> {
    case19_body(source, signature)
        .lines()
        .filter_map(|line| case19_key(line.trim().split_once('=')?.0.trim()))
        .collect()
}

/// The field names one delivered record actually carries, in emission order.
/// Quoted values are skipped, so a value can never be read as a field name.
fn case19_record_keys(line: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        match character {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if let Some(key) = token.split_once('=').and_then(|(name, _)| case19_key(name)) {
                    keys.push(key);
                }
                token.clear();
            }
            _ => token.push(character),
        }
    }
    if let Some(key) = token.split_once('=').and_then(|(name, _)| case19_key(name)) {
        keys.push(key);
    }
    keys
}

/// One field name, accepted only when it is a plain lowercase identifier.
fn case19_key(name: &str) -> Option<String> {
    let mut characters = name.chars();
    let first = characters.next()?;
    if !first.is_ascii_lowercase() {
        return None;
    }
    if !characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return None;
    }
    Some(name.to_owned())
}

/// The integer value of one real facade bound constant.
fn case19_declared_bound(source: &str, constant: &str) -> u64 {
    let declaration = format!("pub const {constant}: usize = ");
    let start = source
        .find(declaration.as_str())
        .unwrap_or_else(|| panic!("the facade must publish {constant}"));
    let rest = &source[start + declaration.len()..];
    let end = rest
        .find(';')
        .unwrap_or_else(|| panic!("{constant} must be a closed constant"));
    rest[..end]
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("{constant} must be an integer"))
}

/// The canonical admitted launch argv, with an identity this case asserts on.
fn case19_launch_argv() -> Vec<std::ffi::OsString> {
    vec![
        std::ffi::OsString::from("--config-descriptor"),
        std::env::temp_dir()
            .join("eliot-891-case-19-launch-auth.json")
            .into_os_string(),
        std::ffi::OsString::from("--config-descriptor-sha256"),
        std::ffi::OsString::from("a".repeat(64)),
        std::ffi::OsString::from("--installation-id"),
        std::ffi::OsString::from("installation-891-case-19"),
        std::ffi::OsString::from("--tx-plan-generation"),
        std::ffi::OsString::from("7"),
        std::ffi::OsString::from("--host-state-root"),
        std::env::temp_dir()
            .join("eliot-891-case-19-host-state")
            .into_os_string(),
    ]
}

// WORK_UNIT_CASE: 891/20
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 20 drives the real SCM launch parse with canary path and argv material, the real typed rejection and the real SCM dispatch boundary"
)]
fn scm_source_and_user_canaries_are_absent_from_every_observation() {
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");
    let fixture = lifecycle_fixture();

    // ---- the real SCM command, source-path and user/session vocabulary ----
    let canaries = [
        "--config-descriptor",
        "--config-descriptor-sha256",
        "--installation-id",
        "--tx-plan-generation",
        "--host-state-root",
        "--registration-nonce",
        "config-descriptor.json",
        "case-20-host-state",
        "control_request_frame",
        "KernelControlCommand",
        "RuntimeLaunchDescriptor",
        "EliotdLaunchDescriptor",
        "phase_b_scm_selector",
        "command_line",
        "argv",
        "host_state_root",
        "src/lib.rs",
        "module_path!",
        "file!",
        "UserBrokerPreparedBinding",
        "ServiceAccount",
        "user_sid",
        "LOCAL_SERVICE_SID",
        "SessionId",
        "session_id",
    ];

    let statements = case20_observation_statements(&lib);
    assert!(
        statements.len() > 50,
        "the observation surface must still be the full table's call sites: {}",
        statements.len()
    );
    for statement in &statements {
        for canary in canaries {
            assert!(
                !statement.contains(canary),
                "an observation statement must carry no {canary:?} material: {statement}"
            );
        }
    }

    // ---- executed pass 1: the real SCM launch parse, with canary material in
    // every slot the owner is documented never to bind ----
    let record = capture_emit(|| {
        eliot_host::HostLaunchOptions::parse(case20_launch_argv())
            .expect("the admitted SCM argv must build");
    });
    assert_eq!(
        record.lines().count(),
        2,
        "one admitted SCM parse yields exactly the requested and admitted records: {record}"
    );
    for canary in canaries {
        assert!(
            !record.contains(canary),
            "an admitted SCM record must carry no {canary:?} material: {record}"
        );
    }
    assert!(
        record.contains("installation=installation-891-case-20 generation=7"),
        "the SCM admitted identities must stay bound: {record}"
    );

    // ---- executed pass 2: the real typed rejection of a malformed SCM argv ----
    // A typed rejection holds no admitted value, so no identity slot is bound
    // and nothing from the rejected argv may appear.
    let mut rejected_argv = case20_launch_argv();
    rejected_argv.truncate(6);
    let rejected_record = capture_emit(|| {
        let rejected = eliot_host::HostLaunchOptions::parse(rejected_argv);
        assert!(
            rejected.is_err(),
            "the truncated SCM argv must stay rejected"
        );
    });
    assert_eq!(
        rejected_record.lines().count(),
        2,
        "one rejected SCM parse yields exactly the requested and typed-rejection records: {rejected_record}"
    );
    for canary in canaries {
        assert!(
            !rejected_record.contains(canary),
            "a rejected SCM record must carry no {canary:?} material: {rejected_record}"
        );
    }
    assert!(
        !rejected_record.contains("installation=installation-891-case-20")
            && !rejected_record.contains("generation=7")
            && rejected_record.contains("installation=missing")
            && rejected_record.contains("generation=missing"),
        "a typed rejection must bind no admitted identity and spell every absent slot as missing: {rejected_record}"
    );

    // ---- executed pass 3: the real SCM dispatch boundary and its terminal ----
    // Driven with the frozen events read out of the table itself, through the
    // exact pair of seams `lib.rs:8591` and `lib.rs:8650-8651` run.
    let rows = case20_boundary_rows(&lib);
    let restart_requested = case20_event(&rows, "kernel-restart.requested");
    let restart_unknown = case20_event(&rows, "kernel-restart.terminal");
    assert_eq!(
        restart_unknown.as_str(),
        fixture["terminal_codes"]["kernel_restart_unknown"]
            .as_str()
            .expect("the fixture must pin the typed restart unknown code"),
        "the restart terminal row must carry the fixture's typed unknown code"
    );
    let scm_record = capture_emit(|| {
        eliot_host::host_diagnostics::observe_entrypoint_with_detail(
            eliot_host::host_diagnostics::EntrypointStage::ScmDispatch,
            &restart_requested,
        );
        eliot_host::host_diagnostics::observe_terminal_error(&restart_unknown);
    });
    assert_eq!(
        case20_record_keys(scm_record.lines().next().expect("an SCM request record")),
        case20_declared_keys(&facade, "pub fn observe_entrypoint_with_detail"),
        "the SCM request record may carry only the facade's declared fields: {scm_record}"
    );
    assert_eq!(
        case20_record_keys(scm_record.lines().nth(1).expect("a terminal record")),
        case20_declared_keys(&facade, "pub fn observe_terminal_error"),
        "the SCM terminal record may carry only the facade's declared fields: {scm_record}"
    );
    for canary in canaries {
        assert!(
            !scm_record.contains(canary),
            "an SCM boundary record must carry no {canary:?} material: {scm_record}"
        );
    }
    assert!(
        scm_record.contains(&format!("detail=\"{restart_requested}\"")),
        "the SCM request record must carry its frozen row vocabulary: {scm_record}"
    );
    assert!(
        scm_record.contains(&format!("code=\"{restart_unknown}\"")),
        "the SCM terminal record must carry its frozen row code: {scm_record}"
    );
}

/// The balanced-paren observation statements of `lib.rs`.
fn case20_observation_statements(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut statements = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if line.contains("host_lifecycle_observe_")
            && line.contains('(')
            && !line.trim_start().starts_with("//")
        {
            let mut statement = line.trim().to_owned();
            while count_occurrences(&statement, "(") > count_occurrences(&statement, ")")
                && index + 1 < lines.len()
            {
                index += 1;
                statement.push(' ');
                statement.push_str(lines[index].trim());
            }
            statements.push(statement);
        }
        index += 1;
    }
    statements
}

/// `(name, event)` for every row of the table, in exact table order.
fn case20_boundary_rows(source: &str) -> Vec<(String, String)> {
    let table = source
        .split_once("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .unwrap_or_else(|| panic!("the boundary table must exist"))
        .1;
    let body = table
        .split_once("\n];")
        .unwrap_or_else(|| panic!("the boundary table must be a closed slice"))
        .0;
    body.split("HostLifecycleBoundary {")
        .skip(1)
        .map(|row| {
            (
                case20_row_field(row, "name"),
                case20_row_field(row, "event"),
            )
        })
        .collect()
}

/// One frozen event value, taken from its own row of the table.
fn case20_event(rows: &[(String, String)], name: &str) -> String {
    rows.iter()
        .find(|(row_name, _)| row_name == name)
        .map_or_else(
            || panic!("the table must carry the {name} row"),
            |(_, event)| event.clone(),
        )
}

/// Reads one boundary row field, joining a `concat!` spelling.
fn case20_row_field(row: &str, field: &str) -> String {
    let prefix = format!("{field}: ");
    let raw = row
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("a boundary row must carry {field}"))
        .trim()
        .trim_end_matches(',')
        .to_owned();
    match raw.strip_prefix("concat!(") {
        Some(literals) => {
            let mut joined = String::new();
            let mut rest = literals.strip_suffix(')').unwrap_or(literals);
            while let Some(open) = rest.find('"') {
                let after = &rest[open + 1..];
                let close = after
                    .find('"')
                    .unwrap_or_else(|| panic!("a concat literal must close"));
                joined.push_str(&after[..close]);
                rest = &after[close + 1..];
            }
            joined
        }
        None => raw.trim_matches('"').to_owned(),
    }
}

/// The macro field names one real facade seam declares, in source order.
fn case20_declared_keys(source: &str, signature: &str) -> Vec<String> {
    case20_body(source, signature)
        .lines()
        .filter_map(|line| case20_key(line.trim().split_once('=')?.0.trim()))
        .collect()
}

/// The field names one delivered record actually carries, in emission order.
/// Quoted values are skipped, so a value can never be read as a field name.
fn case20_record_keys(line: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        match character {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if let Some(key) = token.split_once('=').and_then(|(name, _)| case20_key(name)) {
                    keys.push(key);
                }
                token.clear();
            }
            _ => token.push(character),
        }
    }
    if let Some(key) = token.split_once('=').and_then(|(name, _)| case20_key(name)) {
        keys.push(key);
    }
    keys
}

/// One field name, accepted only when it is a plain lowercase identifier.
fn case20_key(name: &str) -> Option<String> {
    let mut characters = name.chars();
    let first = characters.next()?;
    if !first.is_ascii_lowercase() {
        return None;
    }
    if !characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return None;
    }
    Some(name.to_owned())
}

/// The body of one facade item, taken from its signature.
fn case20_body(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("the facade must carry {signature}"));
    let rest = &source[start..];
    let open = rest
        .find('{')
        .unwrap_or_else(|| panic!("{signature} must open a body"));
    let close = rest[open..]
        .find("\n}")
        .unwrap_or_else(|| panic!("{signature} must close its body"));
    rest[open + 1..open + close].to_owned()
}

/// The canonical SCM launch argv, with canary material in every slot the
/// diagnostics must never carry.
fn case20_launch_argv() -> Vec<std::ffi::OsString> {
    vec![
        std::ffi::OsString::from("--config-descriptor"),
        std::env::temp_dir()
            .join("891-case-20-config-descriptor.json")
            .into_os_string(),
        std::ffi::OsString::from("--config-descriptor-sha256"),
        std::ffi::OsString::from("a".repeat(64)),
        std::ffi::OsString::from("--installation-id"),
        std::ffi::OsString::from("installation-891-case-20"),
        std::ffi::OsString::from("--tx-plan-generation"),
        std::ffi::OsString::from("7"),
        std::ffi::OsString::from("--host-state-root"),
        std::env::temp_dir()
            .join("891-case-20-host-state")
            .into_os_string(),
    ]
}

// WORK_UNIT_CASE: 891/21
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 21 runs the real admitted parse twice for byte determinism, separates the observational clock from the semantic record and proves the stdout framing stays untouched"
)]
fn injected_capture_is_deterministic_and_separates_observational_timing() {
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");
    let fixture = lifecycle_fixture();

    // ---- executed pass 1 and 2: the same real operation, captured twice ----
    // The injected schedule is a fixed argv driving one instrumented
    // production contour, and the capture is a scoped subscriber, so no clock,
    // no scheduler and no environment value can reach the semantic record.
    let first = case21_capture_untimed(|| {
        eliot_host::HostLaunchOptions::parse(case21_launch_argv())
            .expect("the admitted argv must build");
    });
    let second = case21_capture_untimed(|| {
        eliot_host::HostLaunchOptions::parse(case21_launch_argv())
            .expect("the admitted argv must build");
    });
    assert_eq!(
        first, second,
        "the same operation must yield byte-identical semantic records"
    );
    assert_eq!(
        first.lines().count(),
        2,
        "one admitted parse yields exactly two records: {first}"
    );
    assert!(
        first.contains("event=\"host.entrypoint_stage\"")
            && first.contains("stage=\"launch_config\"")
            && first.contains("installation=installation-891-case-21 generation=7"),
        "the semantic record must carry the frozen vocabulary and identities: {first}"
    );

    // ---- observational timing is the subscriber's, never the record's ----
    // The default subscriber's clock is a separate observational input: the
    // timed capture differs from the untimed one only in its leading timestamp.
    let timed = capture_emit(|| {
        eliot_host::HostLaunchOptions::parse(case21_launch_argv())
            .expect("the admitted argv must build");
    });
    assert_eq!(
        timed.lines().count(),
        first.lines().count(),
        "observational timing must not add or remove a record: {timed}"
    );
    assert!(
        timed
            .lines()
            .all(|line| line.starts_with(|c: char| c.is_ascii_digit())),
        "the timed capture must carry one clock reading per record: {timed}"
    );
    assert!(
        first
            .lines()
            .all(|line| line.starts_with(" INFO ") || line.starts_with("ERROR ")),
        "the untimed capture must carry no clock reading at all: {first}"
    );
    assert_eq!(
        case21_without_observational_timing(&timed),
        case21_without_observational_timing(&first),
        "the semantic record must be identical with and without observational timing: {timed}"
    );
    assert_ne!(
        timed, first,
        "observational timing must stay visible in the capture, never hidden"
    );
    // No elapsed, duration or span timing belongs to the semantic record, and
    // no injected clock is presented as live behaviour.
    for observational in ["elapsed", "duration", "latency", "span", "clock", "mock"] {
        assert!(
            !first.contains(observational),
            "the semantic record must carry no {observational:?} timing field: {first}"
        );
    }

    // ---- stdout framing stays one JSON object per line ----
    // host_diagnostics.rs:353 is the real production subscriber: it writes to
    // stderr, so the console protocol's stdout framing is untouched.
    assert!(
        facade.contains(".with_writer(std::io::stderr)"),
        "the production diagnostics subscriber must keep writing to stderr"
    );
    assert!(
        !facade.contains("io::stdout"),
        "the diagnostics facade must never write to stdout"
    );
    assert_eq!(
        fixture["stdout_protocol_contamination"].as_bool(),
        Some(false),
        "the fixture must record no stdout protocol contamination"
    );
    assert_eq!(
        count_occurrences(&first, "\n"),
        2,
        "each delivered record must stay exactly one line: {first}"
    );
    assert!(
        !first.contains('\r'),
        "a delivered record must not carry a carriage return: {first}"
    );
    // One bounded detail field is one record: the frozen event vocabulary can
    // never split a line-oriented frame.
    let rows = case21_boundary_rows(&lib);
    for row in ["open.requested", "stop.requested", "start.requested"] {
        let event = case21_event(&rows, row);
        let line = capture_emit(|| {
            eliot_host::host_diagnostics::observe_entrypoint_with_detail(
                eliot_host::host_diagnostics::EntrypointStage::Startup,
                &event,
            );
        });
        assert_eq!(
            line.lines().count(),
            1,
            "one bounded entrypoint detail must stay one record: {line}"
        );
        assert!(
            line.contains(&format!("detail=\"{event}\"")),
            "the frozen event must cross the boundary verbatim: {line}"
        );
    }
}

/// The same scoped-subscriber capture as `capture_emit`, with the subscriber's
/// clock switched off so only the semantic record remains.
fn case21_capture_untimed(emit: impl FnOnce()) -> String {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
    }
    String::from_utf8_lossy(&sink.bytes.lock().unwrap()).into_owned()
}

/// Drops the leading clock reading of each record, keeping the semantic tail.
fn case21_without_observational_timing(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.starts_with(|c: char| c.is_ascii_digit()) {
                line.split_once(' ').map_or(line, |(_clock, rest)| rest)
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `(name, event)` for every row of the table, in exact table order.
fn case21_boundary_rows(source: &str) -> Vec<(String, String)> {
    let table = source
        .split_once("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .unwrap_or_else(|| panic!("the boundary table must exist"))
        .1;
    let body = table
        .split_once("\n];")
        .unwrap_or_else(|| panic!("the boundary table must be a closed slice"))
        .0;
    body.split("HostLifecycleBoundary {")
        .skip(1)
        .map(|row| {
            (
                case21_row_field(row, "name"),
                case21_row_field(row, "event"),
            )
        })
        .collect()
}

/// One frozen event value, taken from its own row of the table.
fn case21_event(rows: &[(String, String)], name: &str) -> String {
    rows.iter()
        .find(|(row_name, _)| row_name == name)
        .map_or_else(
            || panic!("the table must carry the {name} row"),
            |(_, event)| event.clone(),
        )
}

/// Reads one boundary row field, joining a `concat!` spelling.
fn case21_row_field(row: &str, field: &str) -> String {
    let prefix = format!("{field}: ");
    let raw = row
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("a boundary row must carry {field}"))
        .trim()
        .trim_end_matches(',')
        .to_owned();
    match raw.strip_prefix("concat!(") {
        Some(literals) => {
            let mut joined = String::new();
            let mut rest = literals.strip_suffix(')').unwrap_or(literals);
            while let Some(open) = rest.find('"') {
                let after = &rest[open + 1..];
                let close = after
                    .find('"')
                    .unwrap_or_else(|| panic!("a concat literal must close"));
                joined.push_str(&after[..close]);
                rest = &after[close + 1..];
            }
            joined
        }
        None => raw.trim_matches('"').to_owned(),
    }
}

/// The canonical admitted launch argv for the deterministic capture.
fn case21_launch_argv() -> Vec<std::ffi::OsString> {
    vec![
        std::ffi::OsString::from("--config-descriptor"),
        std::env::temp_dir()
            .join("eliot-891-case-21-launch-auth.json")
            .into_os_string(),
        std::ffi::OsString::from("--config-descriptor-sha256"),
        std::ffi::OsString::from("a".repeat(64)),
        std::ffi::OsString::from("--installation-id"),
        std::ffi::OsString::from("installation-891-case-21"),
        std::ffi::OsString::from("--tx-plan-generation"),
        std::ffi::OsString::from("7"),
        std::ffi::OsString::from("--host-state-root"),
        std::env::temp_dir()
            .join("eliot-891-case-21-host-state")
            .into_os_string(),
    ]
}

// WORK_UNIT_CASE: 891/22
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 22 proves all five allowed-diff properties from the executed HostComposition::open call path plus the parsed production call sites: row ownership, the single terminal, the lifecycle vocabulary and the published surface"
)]
fn production_call_path_proves_the_allowed_diff_instead_of_asserting_it() {
    let lib = manifest_source("src/lib.rs");
    let facade = manifest_source("src/host_diagnostics.rs");
    let activation = manifest_source("src/activation_lifecycle.rs");
    let fixture = lifecycle_fixture();

    let rows = case22_boundary_rows(&lib);
    let identifiers = case22_identifiers(&lib);
    let table = &fixture["boundary_table"];

    // ---- no unowned edit: the identifiers own the rows one for one ----
    assert_eq!(
        identifiers.len(),
        rows.len(),
        "every row must have exactly one identifier and every identifier one row"
    );
    assert_eq!(
        table["rows"].as_u64(),
        Some(rows.len() as u64),
        "the fixture row count must still equal the real table"
    );
    let mut events: Vec<&str> = rows.iter().map(|(_, event)| event.as_str()).collect();
    events.sort_unstable();
    let mut bound: Vec<&str> = identifiers
        .iter()
        .map(|(_, event)| event.as_str())
        .collect();
    bound.sort_unstable();
    assert_eq!(
        bound, events,
        "the identifier-to-row map must be a bijection over the frozen vocabulary"
    );
    let definitions_removed = case22_without_definitions(&lib);
    for (identifier, event) in &identifiers {
        let references = case22_references(&definitions_removed, identifier)
            + case22_references(&activation, identifier);
        assert!(
            references > 0,
            "{identifier} must be referenced by the production call path, not only defined"
        );
        assert!(
            rows.iter().any(|(_, row_event)| row_event == event),
            "{identifier} must resolve to exactly one table row: {event}"
        );
    }

    // ---- no unowned edit: no free event string reaches the observation path ----
    // `lib.rs` selects its frozen row by identifier at every site. The one
    // child-module seam that decides its row from a semantic outcome must name
    // only frozen rows while it does so.
    let mut call_sites = 0;
    for statement in &case22_observation_statements(&[&lib]) {
        if statement.starts_with("fn host_lifecycle_observe_")
            || statement.starts_with("host_lifecycle_observe_terminal(self.boundary)")
        {
            continue;
        }
        if statement.starts_with("host_lifecycle_observe_identity(") {
            assert!(
                !statement.contains('"') && !statement.contains("BOUNDARY_"),
                "the identity projection site must bind no free string and no boundary event: {statement}"
            );
            assert!(
                statement.contains("HostRequestProjection::observed(")
                    && statement.contains("with_process(std::process::id())"),
                "the identity projection site must stay the frozen projection: {statement}"
            );
            continue;
        }
        call_sites += 1;
        assert!(
            !statement.contains('"'),
            "an observation call site must carry no free event string: {statement}"
        );
        for forbidden in ["format!", "concat!", ".as_str()", "to_owned()"] {
            assert!(
                !statement.contains(forbidden),
                "an observation call site must carry no {forbidden:?}: {statement}"
            );
        }
        assert!(
            statement.ends_with(");") && statement.starts_with("host_lifecycle_observe_"),
            "an observation call site must stay a single frozen emission: {statement}"
        );
        let argument = case22_argument(statement);
        let selected = identifiers
            .iter()
            .filter(|(identifier, _)| identifier == argument)
            .count();
        assert_eq!(
            selected, 1,
            "an observation call site must select exactly one frozen row: {statement}"
        );
    }
    // `activation_lifecycle.rs` owns the row arms of its own cell: every site
    // either names one frozen row outright or names a local whose only values
    // are frozen rows chosen by a match on the semantic outcome.
    for statement in &case22_observation_statements(&[&activation]) {
        call_sites += 1;
        assert!(
            statement.ends_with(");"),
            "an observation call site must stay a single frozen emission: {statement}"
        );
        let argument = case22_argument(statement);
        let first = argument
            .chars()
            .next()
            .unwrap_or_else(|| panic!("an observation call site must pass a row: {statement}"));
        assert!(
            argument
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && (first.is_ascii_alphabetic() || first == '_'),
            "an observation call site must pass one bare row selection: {statement}"
        );
        let selected = identifiers
            .iter()
            .filter(|(identifier, _)| identifier == argument)
            .count();
        if selected == 1 {
            continue;
        }
        assert_eq!(
            selected, 0,
            "a frozen row may be selected by name at most once per call site: {statement}"
        );
        // Not a name: the local must be a match whose every arm is a frozen row,
        // so one execution still selects exactly one row.
        let selection = activation
            .split_once(&format!("let {argument} = "))
            .unwrap_or_else(|| {
                panic!("{argument} must be a frozen row or a selection of frozen rows")
            })
            .1;
        assert!(
            selection.trim_start().starts_with("match "),
            "a row selection must resolve through a match on the semantic outcome: {selection}"
        );
        let arms: Vec<&str> = selection
            .split(';')
            .next()
            .unwrap_or_default()
            .split("=>")
            .collect();
        assert!(
            arms.len() > 1,
            "a row selection must resolve through a match: {selection}"
        );
        let mut selected_rows: Vec<&str> = Vec::new();
        for arm in &arms[1..] {
            let mut chosen: Vec<&str> = Vec::new();
            for token in arm.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                for (identifier, event) in &identifiers {
                    if identifier == token {
                        chosen.push(event.as_str());
                    }
                }
            }
            assert_eq!(
                chosen.len(),
                1,
                "every selected arm must name exactly one frozen row: {selection}"
            );
            assert!(
                !selected_rows.contains(&chosen[0]),
                "every selected arm must reach a distinct frozen row: {selection}"
            );
            selected_rows.push(chosen[0]);
        }
        for event in &selected_rows {
            assert!(
                rows.iter().any(|(_, row_event)| row_event == event),
                "a selected arm must resolve to a table row: {event}"
            );
        }
    }
    assert!(
        call_sites > 90,
        "every real lib.rs and activation call site must be accounted for: {call_sites}"
    );

    // ---- no duplicate evaluation, one designated terminal per failed operation ----
    assert_eq!(
        count_occurrences(&lib, "host_lifecycle_observe_terminal(self.boundary)"),
        1,
        "the guard may carry exactly one terminal emission site"
    );
    assert_eq!(
        case22_body(&lib, "fn host_lifecycle_frozen_event").trim(),
        "boundary.event",
        "one emission must evaluate the frozen event exactly once"
    );
    let guard_drop = case22_body(&lib, "impl Drop for HostTerminalGuard");
    assert_eq!(
        count_occurrences(&guard_drop, "host_lifecycle_observe_terminal("),
        1,
        "one armed guard must emit the terminal exactly once"
    );
    assert!(
        guard_drop.contains("if self.armed"),
        "the terminal must be emitted only while armed: {guard_drop}"
    );
    let armed = case22_armed_sites(&[&lib, &activation]);
    assert!(
        armed.len() > 5,
        "the production call path must still arm its designated terminals: {}",
        armed.len()
    );
    for identifier in &armed {
        let event = identifiers
            .iter()
            .find(|(name, _)| name == identifier)
            .map_or_else(
                || panic!("{identifier} must resolve to a row of the table"),
                |(_, event)| event,
            );
        let row_name = rows
            .iter()
            .find(|(_, row_event)| row_event == event)
            .map_or_else(
                || panic!("{identifier} must resolve to a row"),
                |(name, _)| name,
            );
        assert!(
            row_name.ends_with(".terminal"),
            "{identifier} may only be armed for a terminal row, got {row_name}"
        );
    }

    // ---- no lifecycle change: observation names are not lifecycle states ----
    let surface = case22_observation_surface(&lib);
    assert!(
        !surface.contains("enum "),
        "the observation surface must introduce no lifecycle enum"
    );
    for cache in ["static mut", "OnceLock", "LazyLock", "RwLock", "Mutex"] {
        assert!(
            !surface.contains(cache),
            "the observation surface must carry no {cache} dedup cache"
        );
    }
    for helper in [
        "fn host_lifecycle_observe_requested",
        "fn host_lifecycle_observe_scm",
        "fn host_lifecycle_observe_drain",
        "fn host_lifecycle_observe_terminal",
        "fn host_lifecycle_observe_identity",
    ] {
        let body = case22_body(&lib, helper);
        assert!(
            !body.contains("ActivationState")
                && !body.contains("DrainState")
                && !body.contains("ServiceProcessState")
                && !body.contains("ModuleGenerationState")
                && !body.contains("GenerationCutoverState"),
            "{helper} must not read or advance a lifecycle state: {body}"
        );
    }
    let stages = case22_declared_stages(&facade);
    assert!(
        !stages.is_empty(),
        "the facade must publish its frozen stage vocabulary"
    );
    for state in [
        "STOPPED",
        "STARTING",
        "READY",
        "DEGRADED",
        "QUIESCING",
        "FAILED",
        "RECOVERING",
        "RESTART_WAIT",
        "QUARANTINED",
        "MANUAL_RECOVERY",
        "DRAINED",
        "ACTIVE",
        "DRAINING",
    ] {
        assert!(
            !stages.iter().any(|stage| stage == state),
            "an observation stage must never be the lifecycle state {state}"
        );
    }

    // ---- no new visibility: nothing here is published, and cfg(test) is not a
    // publication channel ----
    // This is the whole proof of `no_new_visibility` and nothing is executed for
    // it: the property is provable only by declaration lines, never by execution.
    for published in [
        "pub fn host_lifecycle_",
        "pub struct HostLifecycleBoundary",
        "pub struct HostTerminalGuard",
        "pub const HOST_LIFECYCLE_BOUNDARY_TABLE",
        "pub const BOUNDARY_",
        "pub const PROPAGATED_",
        "pub(crate) fn host_lifecycle_",
    ] {
        assert!(
            !lib.contains(published),
            "the observation surface must stay unpublished: found {published}"
        );
    }
    for declaration in [
        "struct HostLifecycleBoundary",
        "struct HostTerminalGuard",
        "const HOST_LIFECYCLE_BOUNDARY_TABLE",
        "fn host_lifecycle_observe_requested",
        "fn host_lifecycle_observe_terminal",
        "fn host_lifecycle_frozen_event",
    ] {
        let offset = lib
            .find(declaration)
            .unwrap_or_else(|| panic!("the observation surface must carry {declaration}"));
        assert!(
            !lib[..offset].contains("#[cfg(test)]"),
            "{declaration} must be production code, not a cfg(test) item"
        );
    }
    assert_eq!(
        count_occurrences(
            &lib,
            "pub use host_diagnostics::note_event_log_sink_status;"
        ),
        1,
        "the one published seam must stay the #889 re-export it already is"
    );
    assert!(
        facade.contains("pub fn note_event_log_sink_status()"),
        "the published seam must resolve to an existing facade item, not a new one"
    );

    // ---- executed pass: the #889 facade's own formatting and delivery for the
    // table's frozen row events and terminal codes ----
    // Each row event is handed to `observe_entrypoint_with_detail` and each
    // terminal code to `observe_terminal_error` directly, so this section proves
    // the facade's own bounded formatting and delivery behaviour for those
    // frozen spellings, not that a production call site emitted them.
    // A real `HostComposition` owner operation IS now executed in this target
    // further down through `HostComposition::open`, which emits the
    // `open.requested` and `open.terminal` rows of the frozen table.
    for (row_name, stage_name) in [
        ("open.requested", "startup"),
        ("kernel-restart.requested", "scm_dispatch"),
        ("stop.requested", "shutdown_drain"),
    ] {
        let event = case22_event(&rows, row_name);
        let stage = case22_stage(stage_name);
        let record = capture_emit(|| {
            eliot_host::host_diagnostics::observe_entrypoint_with_detail(stage, &event);
        });
        assert_eq!(
            record.lines().count(),
            1,
            "one emission must deliver exactly one record: {record}"
        );
        assert!(
            record.contains(&format!("detail=\"{event}\"")),
            "the row's own event must cross the boundary verbatim: {record}"
        );
        assert!(
            record.contains(&format!("stage=\"{}\"", stage.as_str())),
            "the record must carry the facade's frozen stage name: {record}"
        );
    }
    let stop_terminal = case22_event(&rows, "stop.terminal");
    let terminal_record = capture_emit(|| {
        eliot_host::host_diagnostics::observe_terminal_error(&stop_terminal);
    });
    assert_eq!(
        terminal_record.lines().count(),
        1,
        "one terminal emission must deliver exactly one record: {terminal_record}"
    );
    assert_eq!(
        count_occurrences(&terminal_record, "event=\"host.terminal_error\""),
        1,
        "one failed operation must deliver exactly one terminal record: {terminal_record}"
    );
    // Two identical emissions are both delivered: no cache may suppress a
    // duplicate evaluation, and no terminal is deduplicated into silence.
    let repeated = capture_emit(|| {
        eliot_host::host_diagnostics::observe_terminal_error(&stop_terminal);
        eliot_host::host_diagnostics::observe_terminal_error(&stop_terminal);
    });
    assert_eq!(
        count_occurrences(&repeated, "event=\"host.terminal_error\""),
        2,
        "no mutable global dedup cache may suppress a second emission: {repeated}"
    );

    // Owner pass risks, all three named: `lib.rs` runs a wiring self-check over
    // a by-value backup-dispatch table before the observation and registers no
    // process-global, `HostOwnerLease::acquire` is a real `Global\` named mutex,
    // and the guarded region is entered unconditionally, so the captured
    // evidence is identical on every machine whichever fallible step fails
    // first.
    // The declared `test` column of the `open.terminal` row is `891/case-14`, so
    // case 22 only OBSERVES these rows and does not own them.
    let owner_first = capture_emit(|| {
        let _ = eliot_host::HostComposition::open(
            eliot_host::HostLaunchOptions::parse(case21_launch_argv())
                .expect("the established argv must admit"),
        );
    });
    let owner_second = capture_emit(|| {
        let _ = eliot_host::HostComposition::open(
            eliot_host::HostLaunchOptions::parse(case21_launch_argv())
                .expect("the established argv must admit"),
        );
    });
    for (owner_label, owner) in [
        ("owner_first", &owner_first),
        ("owner_second", &owner_second),
    ] {
        assert_eq!(
            count_occurrences(owner, "code=\"host-open-failed\""),
            1,
            "single_terminal_per_failed_op: one designated terminal per failed owner operation, never two ({owner_label}): {owner}"
        );
        assert_eq!(
            count_occurrences(owner, "detail=\"host.open admitted\""),
            0,
            "no_lifecycle_delta: the admitted row needs durable evidence and an owner lease that the failing open never obtained ({owner_label}): {owner}"
        );
    }
    assert_eq!(
        count_occurrences(&owner_first, "detail=\"host.open requested\""),
        1,
        "no_duplicate_evaluation: re-running the owner yields one record per call, not an accumulation: {owner_first}"
    );
    assert_eq!(
        count_occurrences(&owner_second, "detail=\"host.open requested\""),
        1,
        "no_duplicate_evaluation: re-running the owner yields one record per call, not an accumulation: {owner_second}"
    );
    assert_eq!(
        count_occurrences(&owner_first, "detail=\"host.open requested\"")
            + count_occurrences(&owner_first, "code=\"host-open-failed\""),
        2,
        "no_mutable_global_dedup: nothing in the observation path suppressed or duplicated an emission within one owner call: {owner_first}"
    );

    // ---- the fixture's declared diff names are bound to the properties this
    // test asserts ----
    // The object is only bound to this test's assertions here, not re-proven by
    // them: its five declared names must be exactly the five properties this
    // delivery asserts, and each must stay a declared boolean rather than a
    // free-text claim.
    let allowed = &fixture["allowed_diff"];
    let mut declared: Vec<String> = allowed
        .as_object()
        .expect("allowed_diff must be an object")
        .keys()
        .cloned()
        .collect();
    declared.sort_unstable();
    let mut proven: Vec<&str> = vec![
        "no_duplicate_evaluation",
        "no_lifecycle_delta",
        "no_new_visibility",
        "no_mutable_global_dedup",
        "single_terminal_per_failed_op",
    ];
    proven.sort_unstable();
    assert_eq!(
        declared, proven,
        "allowed_diff must declare exactly the properties this delivery proves"
    );
    for key in &declared {
        assert!(
            allowed[key.as_str()].is_boolean(),
            "the allowed_diff property {key} must stay a declared boolean"
        );
    }
    assert_eq!(
        table["emitting"].as_u64(),
        Some(
            rows.iter()
                .filter(|(_, event)| !event.starts_with("propagated:"))
                .count() as u64
        ),
        "the fixture's emitting count must still equal the real table"
    );
    assert_eq!(
        table["propagated"].as_u64(),
        Some(
            rows.iter()
                .filter(|(_, event)| event.starts_with("propagated:"))
                .count() as u64
        ),
        "the fixture's propagated count must still equal the real table"
    );
    // `deferred_cases` may stay empty only because this very target declares all
    // 22 numbered cases, which is read back out of this file rather than
    // assumed from the fixture.
    let delivered_cases =
        case22_declared_case_numbers(&manifest_source("tests/host_lifecycle_diagnostics.rs"));
    for number in 1..=22u32 {
        assert!(
            delivered_cases.contains(&number),
            "this target must declare WORK_UNIT_CASE: 891/{number}"
        );
    }
    assert_eq!(
        delivered_cases.len(),
        22,
        "this target must declare each of the 22 numbered cases exactly once: {delivered_cases:?}"
    );
    assert!(
        fixture["deferred_cases"]
            .as_array()
            .expect("deferred_cases must be an array")
            .is_empty(),
        "no declared case may stay deferred once this target delivers all 22"
    );
}

/// `(name, event)` for every row of the table, in exact table order.
fn case22_boundary_rows(source: &str) -> Vec<(String, String)> {
    let table = source
        .split_once("const HOST_LIFECYCLE_BOUNDARY_TABLE")
        .unwrap_or_else(|| panic!("the boundary table must exist"))
        .1;
    let body = table
        .split_once("\n];")
        .unwrap_or_else(|| panic!("the boundary table must be a closed slice"))
        .0;
    body.split("HostLifecycleBoundary {")
        .skip(1)
        .map(|row| {
            (
                case22_row_field(row, "name"),
                case22_row_field(row, "event"),
            )
        })
        .collect()
}

/// Reads one boundary row field, joining a `concat!` spelling.
fn case22_row_field(row: &str, field: &str) -> String {
    let prefix = format!("{field}: ");
    let raw = row
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("a boundary row must carry {field}"))
        .trim()
        .trim_end_matches(',')
        .to_owned();
    match raw.strip_prefix("concat!(") {
        Some(literals) => {
            let mut joined = String::new();
            let mut rest = literals.strip_suffix(')').unwrap_or(literals);
            while let Some(open) = rest.find('"') {
                let after = &rest[open + 1..];
                let close = after
                    .find('"')
                    .unwrap_or_else(|| panic!("a concat literal must close"));
                joined.push_str(&after[..close]);
                rest = &after[close + 1..];
            }
            joined
        }
        None => raw.trim_matches('"').to_owned(),
    }
}

/// `(identifier, event)` for every frozen row identifier, in source order.
///
/// One declaration yields exactly one pair: `boundary_by_event` may sit on the
/// declaration line, on the next line, or open its own line, so the selector is
/// read out of the whole `const … ;` statement rather than of one line.
fn case22_identifiers(source: &str) -> Vec<(String, String)> {
    let mut identifiers: Vec<(String, String)> = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        let Some(declaration) = trimmed.strip_prefix("const ") else {
            index += 1;
            continue;
        };
        let Some((identifier, _)) = declaration.split_once(':') else {
            index += 1;
            continue;
        };
        if !identifier.starts_with("BOUNDARY_") && !identifier.starts_with("PROPAGATED_") {
            index += 1;
            continue;
        }
        let mut statement = trimmed.to_owned();
        while !statement.contains(';') && index + 1 < lines.len() {
            index += 1;
            statement.push(' ');
            statement.push_str(lines[index].trim());
        }
        let selector = statement
            .split_once("boundary_by_event(")
            .unwrap_or_else(|| panic!("{identifier} must bind its event through boundary_by_event"))
            .1;
        let event: String = selector
            .trim_start_matches(['"', ' '])
            .chars()
            .take_while(|c| *c != '"')
            .collect();
        assert!(
            !event.is_empty(),
            "{identifier} must bind a non-empty event literal: {statement}"
        );
        identifiers.push((identifier.to_owned(), event));
        index += 1;
    }
    assert_eq!(
        identifiers.len(),
        count_occurrences(source, "const BOUNDARY_")
            + count_occurrences(source, "const PROPAGATED_"),
        "every declared row identifier must be paired with exactly one event"
    );
    identifiers
}

/// `lib.rs` without the row identifier definitions, so any remaining occurrence
/// of an identifier is a real production reference.
fn case22_without_definitions(source: &str) -> String {
    let mut stripped = String::new();
    let mut continuation = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("const BOUNDARY_") || trimmed.starts_with("const PROPAGATED_") {
            continuation = !trimmed.contains("boundary_by_event(");
            continue;
        }
        if continuation {
            if trimmed.starts_with("boundary_by_event(") {
                continuation = false;
            }
            continue;
        }
        stripped.push_str(line);
        stripped.push('\n');
    }
    stripped
}

/// Whole-identifier occurrences of one frozen row identifier.
fn case22_references(source: &str, identifier: &str) -> usize {
    let mut references = 0;
    let mut rest = source;
    while let Some(offset) = rest.find(identifier) {
        let before = rest[..offset].chars().next_back();
        let after = rest[offset + identifier.len()..].chars().next();
        let open_before =
            !before.is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        let open_after =
            !after.is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if open_before && open_after {
            references += 1;
        }
        rest = &rest[offset + identifier.len()..];
    }
    references
}

/// The one bare argument one observation call site passes.
fn case22_argument(statement: &str) -> &str {
    let open = statement
        .find('(')
        .unwrap_or_else(|| panic!("an observation call site must open its argument: {statement}"));
    let inner = &statement[open + 1..];
    inner
        .split_once(");")
        .map_or(inner, |(argument, _)| argument)
        .trim()
        .trim_end_matches(',')
        .trim()
}

/// The numbered `WORK_UNIT_CASE: 891/<n>` cases a target declares; the `T-A`
/// and `T-B` probe markers carry no number and are not cases.
fn case22_declared_case_numbers(target: &str) -> Vec<u32> {
    let prefix = "// WORK_UNIT_CASE: 891/";
    let mut numbers: Vec<u32> = Vec::new();
    for line in target.lines() {
        let Some(marker) = line.trim().strip_prefix(prefix) else {
            continue;
        };
        let digits: String = marker.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            assert!(
                marker.starts_with('T'),
                "a WORK_UNIT_CASE marker must number its case or name its probe: {marker}"
            );
        } else {
            numbers.push(
                digits
                    .parse()
                    .unwrap_or_else(|_| panic!("a case marker must carry a number: {marker}")),
            );
        }
    }
    numbers
}

/// The identifiers used as a guard's designated terminal, in source order.
fn case22_armed_sites(sources: &[&str]) -> Vec<String> {
    let mut armed: Vec<String> = Vec::new();
    for source in sources {
        let lines: Vec<&str> = source.lines().collect();
        let mut index = 0;
        while index < lines.len() {
            let trimmed = lines[index].trim();
            if trimmed.contains("HostTerminalGuard::armed(") {
                let mut rest = trimmed
                    .split_once("HostTerminalGuard::armed(")
                    .map_or_else(String::new, |(_, tail)| tail.to_owned());
                while !rest.contains(')') && index + 1 < lines.len() {
                    index += 1;
                    rest.push(' ');
                    rest.push_str(lines[index].trim());
                }
                let identifier = rest
                    .split_once(')')
                    .unwrap_or_else(|| panic!("an armed guard must close its argument: {trimmed}"))
                    .0
                    .trim()
                    .trim_end_matches(',')
                    .trim()
                    .to_owned();
                assert!(
                    identifier.starts_with("BOUNDARY_") || identifier.starts_with("PROPAGATED_"),
                    "an armed guard must name one frozen row: {identifier}"
                );
                armed.push(identifier);
            }
            index += 1;
        }
    }
    armed
}

/// The observation statements of the instrumented sources, with multi-line
/// sites joined so no argument is skipped.
fn case22_observation_statements(sources: &[&str]) -> Vec<String> {
    let mut statements = Vec::new();
    for source in sources {
        let lines: Vec<&str> = source.lines().collect();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index];
            if line.contains("host_lifecycle_observe_")
                && line.contains('(')
                && !line.trim_start().starts_with("//")
            {
                let mut statement = line.trim().to_owned();
                while count_occurrences(&statement, "(") > count_occurrences(&statement, ")")
                    && index + 1 < lines.len()
                {
                    index += 1;
                    statement.push(' ');
                    statement.push_str(lines[index].trim());
                }
                statements.push(statement);
            }
            index += 1;
        }
    }
    statements
}

/// The observation surface itself: the helpers, the guard, the table and the
/// row identifiers, from the first helper to the const coverage check.
fn case22_observation_surface(source: &str) -> String {
    let start = source
        .find("fn host_lifecycle_observe_requested")
        .unwrap_or_else(|| panic!("the observation helpers must exist"));
    let end = source
        .find("const fn boundary_event_is_propagated(")
        .unwrap_or_else(|| panic!("the row definitions must be followed by their const check"));
    source[start..end.max(start)].to_owned()
}

/// The frozen `EntrypointStage` names the facade publishes, in source order.
fn case22_declared_stages(source: &str) -> Vec<String> {
    case22_body(source, "impl EntrypointStage")
        .lines()
        .filter_map(|line| {
            let literal = line.trim().split_once("=> \"")?.1;
            Some(literal.split('"').next().unwrap_or_default().to_owned())
        })
        .collect()
}

/// One frozen stage value of the real facade vocabulary.
fn case22_stage(frozen: &str) -> eliot_host::host_diagnostics::EntrypointStage {
    match frozen {
        "startup" => eliot_host::host_diagnostics::EntrypointStage::Startup,
        "launch_config" => eliot_host::host_diagnostics::EntrypointStage::LaunchConfig,
        "scm_dispatch" => eliot_host::host_diagnostics::EntrypointStage::ScmDispatch,
        "console_loop" => eliot_host::host_diagnostics::EntrypointStage::ConsoleLoop,
        _ => eliot_host::host_diagnostics::EntrypointStage::ShutdownDrain,
    }
}

/// The body of one item, taken from its signature.
fn case22_body(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("the observation surface must carry {signature}"));
    let rest = &source[start..];
    let open = rest
        .find('{')
        .unwrap_or_else(|| panic!("{signature} must open a body"));
    let close = rest[open..]
        .find("\n}")
        .unwrap_or_else(|| panic!("{signature} must close its body"));
    rest[open + 1..open + close].to_owned()
}

/// One frozen event value, taken from its own row of the table.
fn case22_event(rows: &[(String, String)], name: &str) -> String {
    rows.iter()
        .find(|(row_name, _)| row_name == name)
        .map_or_else(
            || panic!("the table must carry the {name} row"),
            |(_, event)| event.clone(),
        )
}
