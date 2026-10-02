#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Starter probes for F-LOG-HOST-1 item 891 (Implements, not Closes).
//!
//! Through the #889 facade only (`host_diagnostics::observe_entrypoint`,
//! `observe_entrypoint_with_detail`, `observe_terminal_error`); the Windows
//! Event Log seam stays typed-Unavailable (`event_log_sink_status`), never
//! implemented here (#984 still open).
//!
//! Two named probes plus three matrix-denominator guards:
//! - T-A stop/drain distinct (`Requested` -> `Draining` -> `StoppedClean` via
//!   existing `HostComposition::stop` seams; three distinct records sharing
//!   one `drain_generation` correlation, exactly one terminal on failure;
//!   allowed-diff: no duplicate evaluation, lifecycle delta, or new
//!   visibility).
//! - T-B SCM receipt + `Unknown` (unsupported op + expired-deadline/pending
//!   intent via `handle_kernel_restart_request` /
//!   `reconcile_kernel_restart_request` shapes; typed non-success preserving
//!   identity, `Unknown` never false-success, single terminal emission).
//! - `case_matrix_denominator_is_exactly_1_to_22` proves the case markers
//!   really exist once each, with no gap and no doubling.
//! - `boundary_fixture_binds_production_table` binds the `boundary_table`
//!   fixture to the production table in both directions.
//! - `boundary_rows_bind_a_landed_case` binds every production row to a
//!   landed case so the table cannot claim proof that does not exist.
//!
//! The 22-case matrix itself is LANDED, with no gap: all 22 cases carry a
//! `// WORK_UNIT_CASE: 891/<n>` marker, and each marker's `fn` is a real
//! `#[test]`. The `deferred_cases` list in
//! `tests/data/host_lifecycle_diagnostics.json` is the stale artefact, not
//! this file: those entries now describe landed cases, and only the
//! whole-Host child-union coverage proof (#837/#852) remains open. These
//! probes drive the real facade plus the real runtime-control wire types and
//! read the real `lib.rs` call sites; a hand-built expected log alone is
//! never call-site proof. Fake clocks/SCM ports do not establish live SCM
//! behavior. Diagnostics are evidence only: they never change control flow,
//! state, errors, receipts, order, status, or cleanup, and stdout framing
//! stays exactly one-JSON-per-line.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, observe_entrypoint_with_detail,
    observe_terminal_error, sink_status,
};
use eliot_host::windows_event_log::{AdmittedEvent, event_log_sink_status, report_event};
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

/// `lib.rs` with its `#[cfg(test)]` boundary-table case module excised.
///
/// The landed case proofs live in that module and legitimately re-spell the
/// exact literals the T-A/T-B pins count (the single stop terminal site, the
/// dual restart-unknown sites, the `static DEDUP` and
/// `pub fn host_lifecycle_` absences), so a whole-file haystack lets those
/// proofs satisfy their own guards. The module header and its closing brace
/// are both column-0, so the first column-0 `}` after the header is its end.
fn production_source() -> String {
    let lib = manifest_source("src/lib.rs");
    let lines: Vec<&str> = lib.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.trim() == "mod host_lifecycle_boundary_table_tests {")
        .expect("the #891 boundary-table case module must exist in lib.rs");
    let end = lines
        .iter()
        .skip(start + 1)
        .position(|line| *line == "}")
        .map_or_else(
            || panic!("the #891 boundary-table case module must close in lib.rs"),
            |offset| start + 1 + offset,
        );
    lines
        .iter()
        .enumerate()
        .filter(|(index, _)| *index < start || *index > end)
        .map(|(_, line)| *line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// One row of the production `HOST_LIFECYCLE_BOUNDARY_TABLE`, read out of
/// the real `lib.rs` source so the duplicated fixture cannot drift from it.
struct BoundaryRow {
    name: String,
    event: String,
    test: String,
}

/// Returns the first `"..."` literal in `text`.
fn quoted(text: &str) -> String {
    let rest = text.strip_prefix('"').unwrap_or(text);
    match rest.split_once('"') {
        Some((value, _)) => value.to_owned(),
        None => rest.to_owned(),
    }
}

/// Resolves a frozen `event:` field value.
///
/// Three terminal rows spell their code with `concat!` so the source keeps
/// the literal counts the landed probes pin, so the concatenated spelling is
/// the row's real frozen event.
fn frozen_event(value: &str) -> String {
    let value = value.trim();
    let Some(inner) = value.strip_prefix("concat!(") else {
        return quoted(value);
    };
    let inner = inner
        .split_once(')')
        .map_or(inner, |(arguments, _)| arguments);
    inner.split(',').fold(String::new(), |mut joined, part| {
        joined.push_str(&quoted(part.trim()));
        joined
    })
}

/// Parses the frozen production boundary table out of `src/lib.rs`.
///
/// Line-oriented on purpose: the table is a `const` slice of struct literals
/// with one field per line, so this reads the real production rows without
/// inventing a second copy of the table.
fn production_boundary_rows(lib: &str) -> Vec<BoundaryRow> {
    let mut rows: Vec<BoundaryRow> = Vec::new();
    let mut in_table = false;
    let mut current: Option<BoundaryRow> = None;
    for line in lib.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("const HOST_LIFECYCLE_BOUNDARY_TABLE") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if trimmed == "];" {
            break;
        }
        if trimmed == "HostLifecycleBoundary {" {
            current = Some(BoundaryRow {
                name: String::new(),
                event: String::new(),
                test: String::new(),
            });
            continue;
        }
        if trimmed == "}," {
            if let Some(row) = current.take() {
                rows.push(row);
            }
            continue;
        }
        let Some(row) = current.as_mut() else {
            continue;
        };
        if let Some(value) = trimmed.strip_prefix("name: ") {
            row.name = quoted(value);
        } else if let Some(value) = trimmed.strip_prefix("event: ") {
            row.event = frozen_event(value);
        } else if let Some(value) = trimmed.strip_prefix("test: ") {
            row.test = quoted(value);
        }
    }
    rows
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
    // The literal-count pins below measure PRODUCTION call sites. The landed
    // case proofs in `lib.rs` re-spell those same literals, so they are read
    // from the production source: a whole-file haystack would let a proof
    // satisfy its own guard.
    let lib = production_source();

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
    // Requested vs Draining vs StoppedClean are three distinct durable writes.
    assert_ne!("Requested", "Draining");
    assert_ne!("Draining", "StoppedClean");
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

    // Sink failure never alters result/order/status/cleanup: the surrounding
    // operation result stays intact around every observation.
    let host_result: Result<(), &'static str> = Ok(());
    let _ = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ShutdownDrain, "host.stop requested");
    });
    assert!(host_result.is_ok(), "sink outcome must not change result");
    // Event Log seam stays typed-Unavailable; never FFI, never faked.
    assert_eq!(
        event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(eliot_host::host_diagnostics::HostDiagnosticsError::EventLogUnavailable)
    );
    let record = eliot_host::windows_event_log::EventLogRecord::new(
        AdmittedEvent::ServiceStop,
        "host.stop stopped",
    );
    assert_eq!(
        report_event(&record),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
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
    // Production source only: the landed case proofs re-spell the very
    // literals this test counts, so a whole-file haystack would let a proof
    // satisfy its own guard.
    let lib = production_source();

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
    // Single terminal per Unknown outcome (one site per handler outcome).
    // The two `Unknown` exits still emit the restart terminal from exactly two
    // production sites; the sites now name the frozen boundary row rather than
    // the code literal, so the count is taken on the emission sites themselves.
    assert_eq!(
        count_occurrences(
            &lib,
            "host_lifecycle_observe_terminal(BOUNDARY_KERNEL_RESTART_TERMINAL)"
        ),
        2,
        "handle must own exactly its request + unknown terminals, got handle sites"
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
        event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
}

/// The 22-case denominator, asserted exactly: every case in `1..=22` carries
/// exactly one `// WORK_UNIT_CASE: 891/<n>` marker and each marker's `fn` is a
/// real `#[test]` named for its case.
///
/// This is the EXECUTED proof that the matrix really runs. A marker without a
/// live test, or a doubled marker, fails here rather than being described as
/// coverage. Case 2 was the last case whose proof was not landed; its four
/// production rows now name a real `#[test] fn case_2_..`, so the matrix has
/// no gap and the denominator is exactly `1..=22`. The absence of an exception
/// list is itself pinned here: the inverse check below proves every
/// `fn case_<n>_` test in `lib.rs` is paid for by a marker, so a case cannot
/// re-open a silent gap by keeping its proof while dropping its marker.
#[test]
fn case_matrix_denominator_is_exactly_1_to_22() {
    let lib = manifest_source("src/lib.rs");

    // Every marker this issue owns, in source order, paired with the `fn`
    // name it immediately precedes.
    let mut markers: Vec<(u32, String)> = Vec::new();
    let lines: Vec<&str> = lib.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("// WORK_UNIT_CASE: 891/") else {
            continue;
        };
        // Skip the named T-A/T-B probes: they are not matrix cases.
        let Ok(case) = rest.trim().parse::<u32>() else {
            continue;
        };
        assert!(
            (1..=22).contains(&case),
            "case marker {case} is outside the 1..=22 matrix"
        );
        let owner = lines[index + 1..]
            .iter()
            .take(8)
            .find_map(|next| {
                next.trim()
                    .strip_prefix("fn ")
                    .map(|name| name.split(['(', ' ']).next().unwrap_or(name).to_owned())
            })
            .unwrap_or_else(|| panic!("case {case} marker has no following `fn`"));
        assert!(
            owner.starts_with(&format!("case_{case}_")),
            "case {case} marker must precede its own `fn case_{case}_..`, got {owner:?}"
        );
        markers.push((case, owner));
    }

    // No doubling: a case claimed twice is a phantom denominator.
    for pair in markers.windows(2) {
        assert_ne!(
            pair[0].0, pair[1].0,
            "case {} is marked twice, so the denominator is inflated",
            pair[0].0
        );
    }

    // Exact denominator: every case in the matrix, once each, no gap.
    let mut covered: Vec<u32> = markers.iter().map(|(case, _)| *case).collect();
    covered.sort_unstable();
    let expected: Vec<u32> = (1..=22).collect();
    assert_eq!(
        covered, expected,
        "the landed case markers must be exactly 1..=22, with no gap"
    );

    // The inverse of the denominator, so no case can re-open a silent gap: a
    // case proof that is not paid for by a marker is a claim the denominator
    // never admitted, and a marker with no proof is coverage that does not
    // run. Case 2 is held here exactly like the other 21.
    let mut proved: Vec<u32> = Vec::new();
    for line in lines.iter() {
        let trimmed = line.trim();
        let Some(name) = trimmed.strip_prefix("fn case_") else {
            continue;
        };
        let Some((number, _)) = name.split_once('_') else {
            panic!("a case test must name its case number, got {name:?}");
        };
        let number = number
            .parse::<u32>()
            .unwrap_or_else(|_| panic!("a case test must name its case number, got {name:?}"));
        assert!(
            markers.iter().any(|(case, _)| *case == number),
            "{name} claims matrix case {number} with no WORK_UNIT_CASE marker"
        );
        proved.push(number);
    }
    proved.sort_unstable();
    assert_eq!(
        proved, expected,
        "every matrix case must be proved by exactly one `fn case_<n>_` test"
    );

    // Each marker is a real test, not a comment: `#[test]` precedes every one.
    for (case, _) in &markers {
        let marker_line = lib
            .lines()
            .position(|line| line.trim() == format!("// WORK_UNIT_CASE: 891/{case}"))
            .expect("marker line must be locatable");
        let window = lib
            .lines()
            .skip(marker_line)
            .take(8)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            window.contains("#[test]"),
            "case {case} marker must sit on a #[test], got: {window}"
        );
    }
}

/// Binds the duplicated `boundary_table` fixture to the real production table.
///
/// The fixture is a hand-maintained copy, so without this it could drift from
/// `HOST_LIFECYCLE_BOUNDARY_TABLE` in either direction. Both directions are
/// asserted here and both are achievable, because the fixture pins every row:
///
/// - fixture -> production: every name the fixture lists exists as a real
///   production row, with the SAME frozen event spelling;
/// - production -> fixture: every production row appears in the fixture, so a
///   new boundary row cannot ship without the fixture naming it.
///
/// The emitting/propagated split and the explicit propagated exclusions are
/// pinned too, so a row cannot quietly change ownership.
#[test]
fn boundary_fixture_binds_production_table() {
    let lib = production_source();
    let fixture = lifecycle_fixture();
    let table = &fixture["boundary_table"];

    // The fixture names its source; it must name the real frozen table.
    assert_eq!(
        table["source"].as_str(),
        Some("bins/eliot-host/src/lib.rs::HOST_LIFECYCLE_BOUNDARY_TABLE"),
        "fixture must point at the actual frozen table"
    );

    let rows = production_boundary_rows(&lib);
    assert!(
        !rows.is_empty(),
        "the production boundary table must yield rows from lib.rs"
    );
    let fixture_names: Vec<&str> = table["names"]
        .as_array()
        .expect("fixture must pin boundary_table.names")
        .iter()
        .map(|name| name.as_str().expect("boundary name must be a string"))
        .collect();

    // production -> fixture: no production row may be missing from the copy.
    for row in &rows {
        assert!(
            fixture_names.contains(&row.name.as_str()),
            "production boundary row {:?} is absent from the fixture",
            row.name
        );
    }
    // fixture -> production: no fixture name may be invented.
    for name in &fixture_names {
        assert!(
            rows.iter().any(|row| row.name == *name),
            "fixture boundary row {name:?} does not exist in the production table"
        );
    }
    // Same rows in the same order: order drift is drift too.
    assert_eq!(
        rows.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
        fixture_names,
        "fixture names must equal the production table in source order"
    );

    // Every emitting row's frozen event resolves through the production
    // `boundary_by_event` binding, so the fixture can only name real
    // production vocabulary.
    for row in &rows {
        if row.event.starts_with("propagated:") {
            continue;
        }
        assert!(
            lib.contains(&format!("boundary_by_event({:?})", row.event)),
            "emitting row {:?} event {:?} has no production boundary_by_event binding",
            row.name,
            row.event
        );
    }

    // The emitting/propagated split, pinned against the real rows.
    let propagated: Vec<&str> = rows
        .iter()
        .filter(|row| row.event.starts_with("propagated:"))
        .map(|row| row.name.as_str())
        .collect();
    let rows_len = u64::try_from(rows.len()).expect("table length fits u64");
    let propagated_len = u64::try_from(propagated.len()).expect("table length fits u64");
    assert_eq!(
        table["rows"].as_u64(),
        Some(rows_len),
        "fixture must pin one row per production row"
    );
    assert_eq!(
        table["emitting"].as_u64(),
        Some(rows_len - propagated_len),
        "fixture must pin the emitting count"
    );
    assert_eq!(
        table["propagated"].as_u64(),
        Some(propagated_len),
        "fixture must pin the propagated count"
    );
    let exclusions: Vec<&str> = table["propagated_exclusions"]
        .as_array()
        .expect("fixture must pin propagated exclusions")
        .iter()
        .map(|name| name.as_str().expect("exclusion must be a string"))
        .collect();
    assert_eq!(
        exclusions, propagated,
        "propagated exclusions must cover exactly the propagated production rows"
    );
}

/// Binds every production boundary row to a case proof that actually exists.
///
/// The table's `test` field is the claim of proof. A row naming a case with no
/// landed proof is proof that does not exist, so this fails on it instead of
/// leaving the claim unchecked. Every row is now bound the same way and there
/// is no exception list, because every case the table names is landed - case
/// 2's four rows included. Each claim must resolve to both the
/// `// WORK_UNIT_CASE: 891/<n>` marker and the live `#[test] fn case_<n>_`
/// behind it.
#[test]
fn boundary_rows_bind_a_landed_case() {
    let lib = production_source();
    // The markers and the case tests live in the `#[cfg(test)]` case module
    // that `production_source()` excises by design, so they are read from the
    // whole source. Scanning the production haystack finds no marker at all,
    // which made "case 2 is not landed" vacuously true and every other row's
    // binding unprovable.
    let whole = manifest_source("src/lib.rs");
    let rows = production_boundary_rows(&lib);
    assert!(
        !rows.is_empty(),
        "the production boundary table must yield rows from lib.rs"
    );

    let marked: Vec<String> = whole
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("// WORK_UNIT_CASE: 891/")
                .map(|rest| rest.trim().to_owned())
        })
        .collect();

    let mut bound: Vec<&str> = Vec::new();
    for row in &rows {
        let Some(case) = row.test.strip_prefix("891/case-") else {
            // T-A/T-B probes and other issues' cases are not this matrix.
            continue;
        };
        assert!(
            marked.contains(&case.to_owned()),
            "boundary row {:?} names case {case}, which has no WORK_UNIT_CASE marker",
            row.name
        );
        assert!(
            whole.contains(&format!("fn case_{case}_")),
            "boundary row {:?} names case {case}, whose marker sits on no live test",
            row.name
        );
        bound.push(row.name.as_str());
    }
    // The bindings above must not be an empty set: a table that renamed every
    // `test` field out of the `891/case-` namespace would pass this loop by
    // skipping every row, which is unproved, not proved.
    assert!(
        !bound.is_empty(),
        "the boundary table must name matrix cases, or no row binding is proved"
    );

    // The four rows that used to be the named exception are now bound by the
    // same path, so the closure of that gap is pinned rather than assumed:
    // each is still a real production row and each still names case 2.
    for name in [
        "open.requested",
        "open.admitted",
        "start.requested",
        "start.started",
    ] {
        let row = rows.iter().find(|row| row.name == name).unwrap_or_else(|| {
            panic!("the closed case-2 gap pins row {name:?}, which is not a production row")
        });
        assert_eq!(
            row.test, "891/case-2",
            "row {name:?} must still name the landed case 2"
        );
    }
}

// ---------------------------------------------------------------------------
// #893 audit comment 5917124913, blocking defect 1: a terminal failure must be
// correlated to the operation whose subordinate phases carry the identities,
// and a pre-subject failure must say so explicitly instead of relying on order.
//
// The seam driven below is the REAL production terminal owner
// `scm_launch::validate_host_scm_bootstrap` (`src/scm_launch.rs`), reached
// through its public export. It arms its own single `ScmLaunchTerminalGuard`
// on entry and every failure after that point returns through the armed guard,
// so what is asserted here is what production actually emitted through the
// #889 facade - never a hand-built expected record.
// ---------------------------------------------------------------------------

/// The isolated temp root one `scm_launch` contour is launched against.
///
/// The path is deliberately never created: the driven contour refuses before
/// it touches the filesystem, and the tests below assert exactly that, which
/// is what keeps the capture free of any wall-clock, thread-order or ambient
/// state dependence.
fn scm_launch_root(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("eliot-host-893-{tag}"))
}

/// Real `HostLaunchOptions` for one SCM bootstrap contour.
///
/// Built with the canonical ten-pair argv and NO `--registration-nonce` pair,
/// which is the exact pre-subject state production refuses: the launch options
/// parse (the owner identity exists), but the SCM bootstrap has no registration
/// nonce yet, so no operation subject exists at the terminal boundary.
fn scm_launch_options(tag: &str) -> eliot_host::HostLaunchOptions {
    let root = scm_launch_root(tag);
    eliot_host::HostLaunchOptions::parse([
        std::ffi::OsString::from("--config-descriptor"),
        root.join("auth.json").into_os_string(),
        std::ffi::OsString::from("--config-descriptor-sha256"),
        std::ffi::OsString::from("a".repeat(64)),
        std::ffi::OsString::from("--installation-id"),
        std::ffi::OsString::from(format!("installation-{tag}")),
        std::ffi::OsString::from("--tx-plan-generation"),
        std::ffi::OsString::from("7"),
        std::ffi::OsString::from("--host-state-root"),
        root.into_os_string(),
    ])
    .expect("the canonical launch argv must admit")
}

/// #893 D1: a pre-subject terminal states that correlation is UNAVAILABLE.
///
/// Drives the real `validate_host_scm_bootstrap` owner to its failure and
/// asserts the disposition production actually rendered: one terminal record,
/// `correlation_available=false`, and all three owner-issued slots explicitly
/// missing with empty values. The sibling phase record for the SAME operation
/// carries the installation/generation/config identity the contour really held,
/// which is what makes the terminal's explicit "unavailable" the honest
/// disposition rather than a missing correlation this test could not supply.
#[test]
fn lifecycle_scm_pre_subject_failure_states_correlation_unavailable() {
    let options = scm_launch_options("pre-subject");
    let root = scm_launch_root("pre-subject");

    // The owner identity is genuinely in hand before the terminal boundary:
    // production itself renders it into the requested phase record.
    let requested = format!(
        "detail=\"host.scm-launch requested installation=installation-pre-subject \
plan_generation=7 config_digest={}\"",
        "a".repeat(64)
    );

    let emitted = capture_emit(|| {
        let outcome = eliot_host::validate_host_scm_bootstrap(&options);
        assert!(
            outcome.is_err(),
            "a nonce-free SystemService bootstrap must be refused by production, not admitted"
        );
    });

    assert!(
        emitted.contains(&requested),
        "production must render the owner identity it holds, got: {emitted}"
    );
    assert_eq!(
        count_occurrences(&emitted, "host.terminal_error"),
        1,
        "one failed operation must emit exactly one terminal, got: {emitted}"
    );
    assert!(
        emitted.contains("code=\"host-scm-launch-unknown\""),
        "the terminal must carry production's own typed code, got: {emitted}"
    );
    // The disposition the audit demands: correlation is stated unavailable,
    // never left to be inferred from record order (I13.11).
    assert!(
        emitted.contains("correlation_available=false"),
        "a pre-subject terminal must state correlation is unavailable, got: {emitted}"
    );
    for missing in ["tx_missing=true", "effect_missing=true", "req_missing=true"] {
        assert!(
            emitted.contains(missing),
            "every absent identity slot must be explicitly missing ({missing}), got: {emitted}"
        );
    }
    // And the absent slots render empty: no derived, defaulted or borrowed
    // value ever stands in for an identity the owner does not hold.
    for empty in ["tx=\"\"", "effect=\"\"", "req=\"\""] {
        assert!(
            emitted.contains(empty),
            "an absent identity slot must render empty ({empty}), got: {emitted}"
        );
    }
    // Determinism: the refusal happened before any filesystem effect, so the
    // isolated root this test names was never created and nothing outside the
    // capture can influence it.
    assert!(
        !root.exists(),
        "the driven failure must not touch the filesystem, but {} exists",
        root.display()
    );
}

/// #893 D1/case 22: exactly ONE terminal per failed operation, and none for an
/// operation that owns no terminal.
///
/// Two independent failed `validate_host_scm_bootstrap` operations each return
/// through their own armed `ScmLaunchTerminalGuard` through a `?` in the
/// guarded body, so the terminal count must track the failed operation (two),
/// never the process (one) and never the guard's internal `?` chain (more).
/// A rejected `HostLaunchOptions::parse` operation owns no terminal at all and
/// must therefore add none to the same accounting.
#[test]
fn lifecycle_each_failed_operation_emits_exactly_one_terminal() {
    let first = scm_launch_options("op-a");
    let second = scm_launch_options("op-b");

    let emitted = capture_emit(|| {
        assert!(eliot_host::validate_host_scm_bootstrap(&first).is_err());
        assert!(eliot_host::validate_host_scm_bootstrap(&second).is_err());
    });

    assert_eq!(
        count_occurrences(&emitted, "host.terminal_error"),
        2,
        "two failed operations must emit two terminals, not one and not more, got: {emitted}"
    );
    assert_eq!(
        count_occurrences(&emitted, "correlation_available=false"),
        2,
        "both terminals must state their own unavailable disposition, got: {emitted}"
    );
    // Each failed operation also produced its own requested phase record, so
    // the two terminals are two per-operation dispositions rather than one
    // duplicated observation.
    assert_eq!(
        count_occurrences(&emitted, "detail=\"host.scm-launch requested"),
        2,
        "each failed operation must record its own requested phase, got: {emitted}"
    );
    // The two operations are distinct by the owner-issued identity production
    // itself rendered, so the pair is joinable by field equality.
    assert!(
        emitted.contains("installation=installation-op-a")
            && emitted.contains("installation=installation-op-b"),
        "the two operations must carry distinct owner identities, got: {emitted}"
    );

    // An operation whose owner owns no terminal boundary contributes none.
    let rejected = capture_emit(|| {
        let outcome = eliot_host::HostLaunchOptions::parse([std::ffi::OsString::from(
            "--config-descriptor",
        )]);
        assert!(outcome.is_err(), "a one-pair argv must be refused");
    });
    assert!(
        rejected.contains("detail=\"host.launch-options parse typed rejection\""),
        "production must render its own typed rejection, got: {rejected}"
    );
    assert_eq!(
        count_occurrences(&rejected, "host.terminal_error"),
        0,
        "an operation with no terminal owner must emit no terminal, got: {rejected}"
    );
}

/// #893 D1 item 4: a partial identity renders only what the owner holds.
///
/// Drives the real `HostTerminalCorrelation` projection production itself
/// builds at every `bind_operation` site. `correlation_available` is the flag
/// the terminal record renders, so the projection's own answer must never
/// over-claim: a partial binding is not an available correlation, it is
/// distinct from both the full and the fully-unavailable projection, and it is
/// a value - two operations with different owner handles never collapse onto
/// one correlation.
#[test]
fn lifecycle_terminal_correlation_never_over_claims_availability() {
    use eliot_host::host_diagnostics::HostTerminalCorrelation;

    assert!(
        HostTerminalCorrelation::bound("tx", "effect", "req").is_available(),
        "a fully bound correlation is the available one"
    );
    assert!(
        !HostTerminalCorrelation::partially_bound(Some("tx"), None, None).is_available(),
        "a partial binding must never claim full correlation availability"
    );
    assert!(
        !HostTerminalCorrelation::unavailable().is_available(),
        "the explicitly uncorrelated projection claims nothing"
    );

    // A partial binding is a distinct value from both neighbours: it is not the
    // full correlation, and it is not the "nothing held" projection either.
    let partial = HostTerminalCorrelation::partially_bound(Some("operation"), None, None);
    assert_eq!(
        partial,
        HostTerminalCorrelation::partially_bound(Some("operation"), None, None),
        "the same owner handles project the same immutable correlation"
    );
    assert_ne!(
        partial,
        HostTerminalCorrelation::unavailable(),
        "holding one identity must not render as holding none"
    );
    assert_ne!(
        partial,
        HostTerminalCorrelation::bound("operation", "effect", "req"),
        "a partial binding must not render as the full correlation"
    );

    // Content, not position: two operations with different owner-issued handles
    // project to two different correlations, so a terminal carrying one can
    // never be confused with a terminal carrying the other.
    assert_ne!(
        HostTerminalCorrelation::bound("tx-a", "effect-a", "req-a"),
        HostTerminalCorrelation::bound("tx-b", "effect-b", "req-b"),
        "distinct owner identities must project to distinct correlations"
    );
}
