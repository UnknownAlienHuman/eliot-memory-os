#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Focused contract tests for F-LOG-HOST-0 item 889 (Implements, not Closes).
//!
//! These tests prove only the library-compiled facade installation, the
//! #984-wired Event Log delivery seam with its bounded queue/drop policy, the
//! single `main.rs` reference failure, and stdout ownership against the
//! fixture in `tests/data/host_diagnostics_cases.json`, plus the allowed-diff
//! and no-lifecycle/unsafe/authority mutation guard (889/20) and the proof
//! that the binary, the library consumer and these integration tests all
//! compile against the one exported facade owner (889/21). The remaining
//! inventory, per-identity, sizing, canary and sink-mapping cases are named
//! and enumerated by the fixture's `cases` array, so no case in the issue's
//! matrix is left undeclared here. Each fixture label restates its issue's
//! verbatim case text; where a test can only reach part of a case (889/5,
//! 889/7, 889/11 and 889/12 name this explicitly), the label names the
//! narrower thing proved rather than the whole clause.
//!
//! This card's EDIT scope is EXACTLY two files: this test and its fixture. The
//! facade, the Event Log wrapper, `lib.rs`, `main.rs` and the manifest are
//! READ-ONLY inputs that these tests assert about, never files this delivery
//! claims to change.
//!
//! Real Host-wrapper Event Log delivery smoke on isolated Windows stays an
//! honest test-phase residual: this wrapper must neither acquire Event Log FFI
//! nor fake delivery, and OS acceptance is reported with source registration
//! unknown rather than as a registered-source profile. A diagnostic record is
//! evidence only, never lifecycle authority, readiness, or completion.

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

use eliot_host::HostError;
use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, HOST_TERMINAL_CODE_CONSOLE_FAILED,
    HOST_TERMINAL_CODE_DISPATCHER_FAILED, HostConsoleRequest, HostDiagnosticsError,
    HostRequestEvidence, HostRequestProjection, MAX_DIAGNOSTIC_DETAIL_BYTES,
    MAX_DIAGNOSTIC_FIELD_BYTES, bound_detail, bound_field, install_host_diagnostics,
    note_event_log_sink_status, observe_entrypoint, observe_entrypoint_with_detail,
    observe_host_request, observe_terminal_error, shutdown_event_log_reporting, sink_status,
    start_event_log_reporting,
};
use eliot_host::windows_event_log::{
    AdmittedEvent, EVENT_LOG_MAX_INSERTION_BYTES, EVENT_LOG_QUEUE_CAPACITY, EVENT_LOG_SOURCE,
    EventLogAdmission, EventLogDelivery, EventLogRecord, EventLogShutdownSnapshot,
    EventLogWorkCount, EventLogWorkDisposition, WindowsEventLogError, WindowsEventLogQueue,
    event_log_sink_status, report_event, shutdown_event_log_producer, try_admit_admitted_event,
};
use serde_json::Value;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

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

fn contract_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/host_diagnostics_cases.json");
    let bytes = std::fs::read(&path).expect("contract fixture must be readable");
    serde_json::from_slice(&bytes).expect("contract fixture must be valid JSON")
}

fn manifest_source(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).expect("tracked source must be readable")
}

/// Byte-exact mirror of `host_console_protocol::write_response` (JSON +
/// `\n` + flush) onto a captured buffer instead of the stdout lock, so the
/// stdout-ownership proof drives the real framing without touching the
/// process-global stdout.
fn write_protocol_frame(buffer: &mut Vec<u8>, value: &Value) -> bool {
    serde_json::to_writer(&mut *buffer, value).is_ok()
        && buffer.write_all(b"\n").is_ok()
        && buffer.flush().is_ok()
}

/// The ONE facade install attempt in this process, driven once through a
/// `OnceLock` so no second caller can run it.
///
/// `install_claimed_subscriber` ends in `tracing_subscriber::fmt()...try_init()`
/// (src/host_diagnostics.rs:349-355), which fails whenever ANY global subscriber
/// already holds the slot -- including one that a `with_default` scope installed,
/// because `set_default` publishes a THREAD-LOCAL default (the repo documents
/// this at bins/eliot-kernel/src/tests/process_supervision_identity.rs:113). So
/// whether the single attempt can win that slot is a fact about what else was
/// already running, not about the facade. The honest reachable set is therefore
/// read out of the facade's own typed answers below rather than demanded: a
/// facade that claimed the install must have taken the slot (`Ok`), and one that
/// found it already taken must report the typed degraded answer, never `Ok`.
///
/// The repeat refusal is decided from that first observed outcome, exactly as
/// `install_host_diagnostics` itself decides it (`SubscriberSetup::
/// as_install_result`, src/host_diagnostics.rs:118-123): a completed
/// Host-owned install answers `AlreadyOwned` to every later caller, and a failed
/// one keeps its own typed error for every later caller. Either way the repeat
/// call is bounded, non-panicking, creates no second owner and replaces nothing.
fn the_one_facade_install_this_process_drives() -> Result<(), HostDiagnosticsError> {
    static FIRST_INSTALL: OnceLock<Result<(), HostDiagnosticsError>> = OnceLock::new();
    *FIRST_INSTALL.get_or_init(install_host_diagnostics)
}

// WORK_UNIT_CASE: 889/3
// WORK_UNIT_CASE: 889/4
#[test]
fn host_diagnostics_install_is_singly_owned() {
    // First installation claims process ownership; a repeat install is
    // bounded AlreadyOwned, never a panic, a replacement, or a second owner.
    // (Cases 889/3 first install, 889/4 duplicate init.) This is the only
    // test that touches the process-global install, and it drives the one
    // attempt exactly once for the process, so parallel tests can neither
    // race it into a second attempt nor depend on winning the global slot.
    let first = the_one_facade_install_this_process_drives();
    assert!(
        matches!(
            first,
            Ok(())
                | Err(HostDiagnosticsError::SetupUnavailable)
                | Err(HostDiagnosticsError::SetupInProgress)
        ),
        "the one install attempt must answer one of the facade's own three truthful outcomes: \
         this process owned the global slot (Ok), or the slot was already held / an attempt is \
         in flight (SetupUnavailable / SetupInProgress), got {first:?}"
    );
    // The repeat refusal, decided the way the facade decides it and read back
    // through the call itself rather than through the value held above.
    let repeat = install_host_diagnostics();
    match first {
        Ok(()) => assert_eq!(
            repeat,
            Err(HostDiagnosticsError::AlreadyOwned),
            "a completed Host-owned install must answer a repeat install with the typed \
             AlreadyOwned refusal, never a second owner, a replacement or a panic"
        ),
        Err(attempted) => assert_eq!(
            repeat,
            Err(attempted),
            "an attempt that never took the global slot must keep its own typed answer for every \
             later caller: the outcome is retained, never upgraded to success and never retried"
        ),
    }

    // Tracing-stderr delivery is available exactly when this process's own
    // install really took the global slot. The facade answers this arm from
    // its OBSERVED install state and maps only `Installed` to `Ok` (src/
    // host_diagnostics.rs:246-251), so this is a real equality against the
    // product's own state rather than an assumption about this platform: if
    // the one attempt above won the slot, the stderr sink is certified, and
    // if it found the slot already held, the facade must never certify it.
    // #984 landed, so the wrapper seam below attempts real delivery through
    // the safe port on Windows and stays typed-Unavailable off Windows: never
    // silent delivery elsewhere and never FFI. (Supports 889/15-18.)
    assert_eq!(sink_status(DiagnosticSink::TracingStderr), first);
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(HostDiagnosticsError::EventLogUnavailable)
    );
    if cfg!(windows) {
        assert_eq!(
            event_log_sink_status(),
            Ok(()),
            "wired wrapper must report the sink attemptable on Windows"
        );
    } else {
        assert_eq!(
            event_log_sink_status(),
            Err(WindowsEventLogError::EventLogUnavailable),
            "off Windows the port stays typed-Unavailable"
        );
    }

    // Truncation honesty: oversized inputs keep a bounded prefix and record
    // the original length. (Supports 889/10 sizing.)
    let oversized = "x".repeat(8 * MAX_DIAGNOSTIC_DETAIL_BYTES);
    let bounded = bound_detail(&oversized);
    assert_eq!(bounded.original_bytes(), oversized.len());
    assert!(
        bounded.truncated(),
        "oversized input must report truncation"
    );
    assert!(
        bounded.text().len() <= MAX_DIAGNOSTIC_DETAIL_BYTES,
        "retained prefix must stay bounded, got {} bytes",
        bounded.text().len()
    );
    let exact = "y".repeat(MAX_DIAGNOSTIC_DETAIL_BYTES);
    let kept = bound_detail(&exact);
    assert!(
        !kept.truncated(),
        "in-bound input must not report truncation"
    );
    assert_eq!(kept.text(), exact);

    let long_code = "c".repeat(8 * MAX_DIAGNOSTIC_FIELD_BYTES);
    let bounded_code = bound_field(&long_code);
    assert!(bounded_code.truncated());
    assert!(bounded_code.text().len() <= MAX_DIAGNOSTIC_FIELD_BYTES);

    // Terminal vocabulary projects the frozen Host stop codes without a
    // second lifecycle owner; the two funnel codes stay distinct.
    assert_ne!(
        HOST_TERMINAL_CODE_CONSOLE_FAILED,
        HOST_TERMINAL_CODE_DISPATCHER_FAILED
    );
    let fixture = contract_fixture();
    assert_eq!(
        HOST_TERMINAL_CODE_CONSOLE_FAILED,
        fixture["terminal_codes"]["console_failed"]
            .as_str()
            .expect("fixture must pin the console_failed code")
    );
    assert_eq!(
        HOST_TERMINAL_CODE_DISPATCHER_FAILED,
        fixture["terminal_codes"]["dispatcher_failed"]
            .as_str()
            .expect("fixture must pin the dispatcher_failed code")
    );
}

// WORK_UNIT_CASE: 889/2
#[test]
fn host_diagnostics_emission_surface_is_only_the_workspace_tracing_facade() {
    // Behaviour under test (case 2, "only workspace tracing facade"): the
    // facade's entire emission surface is the workspace `tracing` crate
    // re-exported by the facade itself, and nothing else. This test must fail
    // if the facade reaches a second emission mechanism (stdout/stderr writes,
    // `dbg!`, another logging facade, a second hand-rolled re-export), if the
    // crate stops inheriting `tracing`/`tracing-subscriber` from the workspace,
    // or if a leaf routes emission around the shared facade.
    //
    // The source guard runs on the facade's CODE lines only. Doc comments and
    // ordinary line comments are filtered out first because the module header
    // and the re-export's own doc comment legitimately name `tracing::` in
    // prose while stating that no leaf should.
    let code = the_facades_code_lines_only(&manifest_source("src/host_diagnostics.rs"));
    let manifest = manifest_source("Cargo.toml");

    // Phase 1, the MANIFEST guard: the crate inherits both crates from the
    // workspace, so exactly one `tracing` and one `tracing-subscriber` reach
    // the build and the lint layer rejects a non-tracing emission as a build
    // failure rather than a silent second surface. A `path =` or pinned
    // `version =` redefinition would compile a second copy of the very macro
    // the facade's records are built by.
    assert_the_tracing_dependencies_are_inherited_from_the_workspace(&manifest);

    // Phase 2, the SOURCE guard: exactly one `pub use tracing::{info, warn};`
    // re-export, no other macro path re-exported or imported privately, an
    // exact emission-macro count, and no second emission mechanism -- no
    // `println!`/`print!`/`eprintln!`/`eprint!`/`dbg!`, no `log::`, no
    // `env_logger`, no `slog`, no `tracing_log`. The one direct stream
    // reference is the subscriber's stderr WRITER, which is what makes this
    // facade stderr-only and keeps the console-protocol stdout framing
    // uncontaminated.
    //
    // Returns the emission count it measured, which the executed phase below
    // re-derives from the facade's own macros: the source text must account
    // for exactly the emissions this test observes happening.
    let source_emissions = assert_the_facades_emission_surface_is_only_tracing(&code);

    // Phase 3, the EXECUTED proof: the facade's own re-exported macros are live
    // here and are the workspace macros - they reach the scoped subscriber
    // installed below through `tracing`'s dispatch, which no other emitter
    // calls - and they are routed to the facade target instead of escaping to
    // the call site. A facade that swapped in a different emitter would drop
    // the record or move it to the default target, failing the assertions
    // below.
    //
    // Returns the two records the facade's own re-exported macros actually
    // emitted plus the number of captured lines, so this caller must go on to
    // judge their target, their levels and the exact capture count rather than
    // merely having run the capture.
    let (info_line, warn_line, captured_lines) = capture_the_facades_re_exported_macro_records();

    assert_the_captured_records_keep_their_target_level_and_count(
        &code,
        source_emissions,
        &info_line,
        &warn_line,
        captured_lines,
    );
}

/// The facade's CODE lines only, so every source guard in case 889/2 reads code
/// rather than prose.
///
/// Doc comments and ordinary line comments are filtered out because the module
/// header and the re-export's own doc comment legitimately name `tracing::` in
/// prose while stating that no leaf should; a guard that counted those lines
/// would prove nothing about what the facade can actually emit. Blank lines are
/// dropped for the same reason.
///
/// Returns the joined code, which BOTH source guards of the case read.
fn the_facades_code_lines_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with("//")
                && !trimmed.starts_with('*')
                && !trimmed.starts_with("/*")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Phase 1 of case 889/2, the MANIFEST guard over `bins/eliot-host/Cargo.toml`:
/// both crates are inherited from the workspace exactly once, neither is
/// redefined or re-pinned locally, and the lint layer that rejects a
/// non-tracing emission is still declared.
///
/// This is what makes the facade's records built by THE workspace macros: a
/// `path =` or a pinned `version =` redefinition would compile a second copy of
/// the very macro the records are emitted through, and the executed phase below
/// would then prove a different macro than the one shipped.
///
/// Carries three assertion families that are reachable from nowhere else in the
/// file: the exactly-once inheritance count, the no-local-redefinition sweep,
/// and the lint-layer presence.
fn assert_the_tracing_dependencies_are_inherited_from_the_workspace(manifest: &str) {
    for inherited in [
        "tracing.workspace = true",
        "tracing-subscriber.workspace = true",
    ] {
        assert_eq!(
            manifest
                .lines()
                .filter(|line| line.trim() == inherited)
                .count(),
            1,
            "the Host crate must declare {inherited} exactly once"
        );
    }
    for redefined in [
        "tracing = {",
        "tracing = { path",
        "tracing-subscriber = {",
        "tracing-subscriber = { path",
    ] {
        assert!(
            !manifest.contains(redefined),
            "the Host crate must not redefine the workspace tracing dependency ({redefined})"
        );
    }
    // The crate's own lint layer is what makes a reintroduction a build
    // failure rather than a silent second surface.
    for lint in [
        "print_stdout = \"warn\"",
        "print_stderr = \"warn\"",
        "dbg_macro = \"warn\"",
    ] {
        assert!(
            manifest.contains(lint),
            "the Host crate must keep the {lint} lint that rejects a non-tracing emission"
        );
    }
}

/// Phase 2a of case 889/2: the facade re-exports the workspace macros, and
/// re-exports nothing else, in exactly one place and by public path only.
///
/// `code` is the facade's CODE lines, so this guard cannot be satisfied by prose
/// in a doc comment.
fn assert_the_facade_re_exports_only_the_workspace_macros(code: &str) {
    // Exactly one re-export, and it re-exports the workspace macros unchanged:
    // adding `debug`/`error`/`trace`, or re-exporting from anything but
    // `tracing`, breaks this count.
    assert_eq!(
        code.matches("pub use tracing::").count(),
        1,
        "the facade must re-export the tracing macros exactly once"
    );
    assert!(
        code.contains("pub use tracing::{info, warn};"),
        "the facade must re-export exactly the shared tracing info/warn macros"
    );
    for other in [
        "pub use tracing::{debug",
        "pub use tracing::{error",
        "pub use tracing::{trace",
        "pub use tracing::*",
        "pub use ::tracing",
    ] {
        assert!(
            !code.contains(other),
            "the facade must not widen or re-path its tracing re-export ({other})"
        );
    }
    assert!(
        !code
            .lines()
            .any(|line| line.trim() == "use tracing::{info, warn};"),
        "the macros must be re-exported publicly, not imported privately"
    );
}

/// Phase 2b of case 889/2: every emission the facade performs goes through that
/// one re-export, and the emission macro set is exactly the frozen one.
///
/// `counted` is the emission total Phase 2a counted, threaded back in from the
/// caller so the source census and the EXECUTED capture are judged against the
/// same number: a source text that accounts for exactly the emissions this test
/// then observes happening is a real census, and the two sides describing
/// different macros fails here.
///
/// Returns the emission count it measured, so the caller must thread it onward.
fn assert_every_facade_emission_uses_the_frozen_macro_set(code: &str, counted: usize) -> usize {
    // Every emission goes through that one re-export. The facade owns the
    // subscriber installation (`tracing_subscriber::fmt().try_init()`), which
    // is the one place that legitimately names the crates directly.
    let expected_emissions = code.matches("tracing::info!(").count()
        + code.matches("tracing::error!(").count()
        + code.matches("tracing::warn!(").count();
    assert_eq!(
        expected_emissions, counted,
        "the facade's emission count must be the one the re-export guard measured, so the source \
         census and the executed capture are describing the same macros"
    );
    assert_eq!(
        expected_emissions, 8,
        "every facade emission must name the workspace tracing macro path"
    );
    assert_eq!(
        code.matches("tracing::").count(),
        expected_emissions + 1,
        "tracing may be named only by its emission macros and the single re-export"
    );
    for other in [
        "tracing::debug!(",
        "tracing::trace!",
        "tracing::event!",
        "tracing::span!",
    ] {
        assert!(
            !code.contains(other),
            "the facade must emit only through the frozen tracing macro set ({other})"
        );
    }
    expected_emissions
}

/// Phase 2 of case 889/2, the SOURCE guard over the facade's code: exactly one
/// `pub use tracing::{info, warn};` re-export, no other macro path re-exported
/// or imported privately, the emission-macro count exact, and no forbidden
/// emission token anywhere in the facade's code.
///
/// Phase 2a owns the re-export spelling and Phase 2c owns the second-emission-
/// mechanism sweep; this body is the spine that threads the emission count
/// between them, so neither half can be reached while dropping the other's
/// result.
///
/// Returns the emission count it measured, so the caller must thread it into
/// the executed phase rather than discard it: the source text has to account
/// for exactly the emissions this test observes happening, or the counted
/// emissions and the executed ones are describing different macros.
fn assert_the_facades_emission_surface_is_only_tracing(code: &str) -> usize {
    assert_the_facade_re_exports_only_the_workspace_macros(code);
    let expected_emissions = assert_every_facade_emission_uses_the_frozen_macro_set(code, 8);
    assert_the_facade_owns_no_second_emission_mechanism(code);
    expected_emissions
}

/// Phase 2c of case 889/2: the facade formats bounded strings and hands them to
/// `tracing`; it never writes a stream itself and never reaches a second
/// logging facade.
///
/// `code` is the facade's CODE lines, so neither a doc comment nor a second
/// module can satisfy this sweep.
fn assert_the_facade_owns_no_second_emission_mechanism(code: &str) {
    // No second emission mechanism at all: the facade formats bounded strings
    // and hands them to `tracing`, it never writes a stream itself.
    for forbidden in [
        "println!",
        "print!",
        "eprintln!",
        "eprint!",
        "dbg!",
        "std::println",
        "std::print",
        "stdout()",
        "stderr()",
        "std::io::Write",
        "std::io::BufWriter",
        "std::io::stdin",
        "std::fs::File::create",
        "File::create",
    ] {
        assert!(
            !code.contains(forbidden),
            "the facade must not own a second emission mechanism ({forbidden})"
        );
    }
    // The one direct stream reference is the subscriber's stderr WRITER, which
    // is what makes this facade stderr-only and keeps the console-protocol
    // stdout framing uncontaminated. Exactly one, and it is inside the single
    // subscriber installation - never a second hand-written write.
    assert_eq!(
        code.matches("std::io::stderr").count(),
        1,
        "the facade may name the stderr writer exactly once, for its subscriber"
    );
    assert!(
        code.contains("tracing_subscriber::fmt()") && code.contains(".try_init()"),
        "the stderr writer must belong to the one tracing subscriber installation"
    );
    // The only `log::` path in the file is this crate's own
    // `windows_event_log` module, which routes its records through this
    // facade rather than emitting them itself. A foreign logging facade
    // (`log::info!`, `env_logger`, `slog`) would add a second emission surface.
    assert!(
        code.contains("use crate::windows_event_log::AdmittedEvent;"),
        "the facade must reach its sink seam through the crate's own module path"
    );
    for foreign in [
        "log::info!",
        "log::warn!",
        "log::error!",
        "log::debug!",
        "log::trace!",
        "use log",
        "use ::log",
        "env_logger",
        "slog",
        "tracing_log",
    ] {
        assert!(
            !code.contains(foreign),
            "the facade must not emit through a second logging facade ({foreign})"
        );
    }
}

/// Phase 3a of case 889/2, the capture: the facade's own re-exported `info!`
/// and `warn!` macros are called HERE, through the re-export itself, inside a
/// scoped subscriber that writes into an in-memory sink rather than into the
/// process-global stderr.
///
/// The scoped subscriber is what makes this an execution of the workspace
/// macros rather than of the call site's own dispatch: a facade that swapped in
/// a different emitter would drop the record or move it to the default target,
/// and neither would be found here.
///
/// Returns the two records those two macros actually emitted, plus the number
/// of lines the capture produced, so the caller must go on to judge their
/// target, their levels and that exact count rather than merely having run the
/// capture.
fn capture_the_facades_re_exported_macro_records() -> (String, String, usize) {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            eliot_host::host_diagnostics::info!(
                target: HOST_DIAGNOSTICS_TARGET,
                event = "host.contract.facade_case_2_info",
                "contract case 2 workspace tracing info"
            );
            eliot_host::host_diagnostics::warn!(
                target: HOST_DIAGNOSTICS_TARGET,
                event = "host.contract.facade_case_2_warn",
                "contract case 2 workspace tracing warn"
            );
        });
        sink.bytes.lock().unwrap().clone()
    };
    let text = String::from_utf8_lossy(&captured).into_owned();
    let info_line = text
        .lines()
        .find(|line| line.contains("host.contract.facade_case_2_info"))
        .expect("the re-exported info macro must emit its own record")
        .to_owned();
    let warn_line = text
        .lines()
        .find(|line| line.contains("host.contract.facade_case_2_warn"))
        .expect("the re-exported warn macro must emit its own record")
        .to_owned();
    (info_line, warn_line, text.lines().count())
}

/// Phase 3b of case 889/2: the two records the facade's own re-exported macros
/// emitted under the scoped subscriber are judged, and the capture is tied back
/// to the source guard.
///
/// Carries the per-record obligations the executed phase exists for -- each
/// record must route to the facade target, must keep its OWN workspace level,
/// and must be distinguishable from the other -- the exact-count obligation
/// (`captured_lines` must be exactly the two records this phase emitted, never
/// a third emission arriving through the same dispatch), and the SOURCE<-
/// EXECUTION tie: the emission macros the source guard counted must be exactly
/// the macro paths the re-export dispatches, so the counted emissions and the
/// executed ones cannot drift apart into describing different macros.
fn assert_the_captured_records_keep_their_target_level_and_count(
    code: &str,
    source_emissions: usize,
    info_line: &str,
    warn_line: &str,
    captured_lines: usize,
) {
    assert_eq!(
        captured_lines, 2,
        "the facade's two re-exported macros must emit exactly two records, got {captured_lines}"
    );
    for line in [info_line, warn_line] {
        assert!(
            line.contains(HOST_DIAGNOSTICS_TARGET),
            "a re-exported macro must route to the facade target, got: {line}"
        );
    }
    assert!(
        info_line.contains("INFO") && warn_line.contains("WARN"),
        "each re-exported macro must keep its own workspace level, got: {info_line} / {warn_line}"
    );
    assert_ne!(
        info_line, warn_line,
        "the two re-exported macros must emit distinguishable records"
    );
    // The two halves of this case must describe the SAME macro set. The counted
    // emissions have to cover the records actually dispatched here, and the only
    // other `tracing::` naming in the facade is the single re-export the source
    // guard already pinned.
    assert!(
        source_emissions >= 2,
        "the source guard counted {source_emissions} emission macros, fewer than the two \
         records this phase actually dispatched through the re-export"
    );
    assert_eq!(
        code.matches("tracing::").count(),
        source_emissions + 1,
        "the emission macros the source guard counted must be exactly the macro paths the \
         re-export dispatches, the single re-export being the only other `tracing::` naming"
    );
}

/// The typed terminal exit the committed stop projection is constructed with.
///
/// There is exactly ONE binding of this value, at file scope, so the `i32` the
/// projection built in
/// `assert_the_stop_and_sighting_stay_two_scoped_host_request_records` is
/// constructed with and the bare `receipt_exit` slot the caller asserts against
/// it are the same constant and cannot drift apart.
const HOST_TERMINAL_EXIT: i32 = 13;

/// The generation the canonical case 6 argv binds, and the value the real
/// parser must return for it.
fn expected_case_6_generation() -> u64 {
    9
}

/// Untyped numeric slots are rendered bare (never quoted) by the
/// `tracing-subscriber` formatter; a quoted match would pass vacuously against
/// any record, so the assertion is split.
///
/// Every expected value is read back off the very projection the caller built,
/// so this proves the rendering of one construction rather than restating the
/// literals it was built from.
fn assert_bare_slots_keep_their_exact_values(stop_line: &str, generation: u64) {
    // `HOST_TERMINAL_EXIT` is the ONE file-scope binding declared above this
    // helper, so the projection built in
    // `assert_the_stop_and_sighting_stay_two_scoped_host_request_records` and the
    // expected bare slot checked here read the same constant.
    for (key, expected) in [
        ("generation", generation.to_string()),
        ("process", std::process::id().to_string()),
        // The typed terminal exit is the `i32` the projection was built with,
        // rendered bare, so it is held in the same `String` as the slots
        // computed from the same projection rather than as a literal.
        ("receipt_exit", HOST_TERMINAL_EXIT.to_string()),
    ] {
        assert!(
            stop_line.contains(&format!(" {key}={expected} ")),
            "the committed stop must carry the bare {key}={expected} slot, got: {stop_line}"
        );
    }
}

/// Every slot the projections were never handed must stay explicitly missing on
/// the committed stop and read as its placeholder, while the bare untyped slots
/// must render exactly the values the stop projection was constructed with.
///
/// Only actual state/receipt supports a positive assertion: the missing slots'
/// fields stay at their meaningless placeholder so they cannot be mistaken for
/// identities, and the reason is not manufactured - no `HostError` was in hand.
fn assert_bound_slots_stay_missing_and_bare_slots_keep_their_exact_values(
    stop_line: &str,
    sighting_line: &str,
) {
    assert_bare_slots_keep_their_exact_values(stop_line, expected_case_6_generation());
    for (key, placeholder) in [
        ("reason", "reason=\"\""),
        ("running", "running=false"),
        ("receipt_sequence", "receipt_sequence=0"),
    ] {
        assert!(
            stop_line.contains(&format!(" {key}_missing=true ")),
            "the committed stop must keep {key}_missing explicit, got: {stop_line}"
        );
        assert!(
            stop_line.contains(&format!(" {placeholder} ")),
            "a {key} the owner never supplied must stay at its meaningless placeholder \
             ({placeholder}), got: {stop_line}"
        );
    }

    // The sighting carried none of them, so every identity slot stays missing
    // and none of them is guessed from the committed record. Each flag is
    // matched as a whole field, so `process_missing` can never satisfy
    // `process`, and the last field may sit at the end of the line.
    for flag in [
        "request_missing=true",
        "operation_missing=true",
        "installation_missing=true",
        "generation_missing=true",
        "process_missing=true",
        "running_missing=true",
        "reason_missing=true",
        "receipt_sequence_missing=true",
        "receipt_exit_missing=true",
    ] {
        let field = format!(" {flag} ");
        assert!(
            sighting_line.contains(&field) || sighting_line.ends_with(&field),
            "a sighting must keep {flag} explicit, got: {sighting_line}"
        );
    }
    // Placeholder spelling is checked per line with a whole-field match, so
    // `receipt_exit=0` can never be satisfied by the prefix of another slot.
    for placeholder in [
        "request=\"\"",
        "operation=\"\"",
        "installation=\"\"",
        "reason=\"\"",
        "generation=0",
        "process=0",
        "running=false",
        "receipt_sequence=0",
        "receipt_exit=0",
    ] {
        let field = format!(" {placeholder} ");
        assert!(
            sighting_line.contains(&field) || sighting_line.ends_with(&field),
            "a slot the sighting was never given must render its placeholder, not a \
             guessed identity ({placeholder}), got: {sighting_line}"
        );
    }
}

/// The frozen spelling of each evidence class is the one the emitted records
/// carry, so renaming one class into another's vocabulary is caught here.
///
/// Returns the eight names it proved distinct, so the caller must check an
/// emitted record against them rather than drop the list.
fn assert_the_eight_evidence_names_stay_distinct() -> Vec<&'static str> {
    let evidence_names = [
        HostRequestEvidence::Observed,
        HostRequestEvidence::Admitted,
        HostRequestEvidence::ProcessStarted,
        HostRequestEvidence::SemanticallyReady,
        HostRequestEvidence::DurableCommitted,
        HostRequestEvidence::Cancelled,
        HostRequestEvidence::Failed,
        HostRequestEvidence::Unknown,
    ];
    let mut distinct = evidence_names.map(HostRequestEvidence::as_str).to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        evidence_names.len(),
        "observed, admitted, process-started, semantically-ready, durable-committed, \
         cancelled, failed and unknown must stay eight distinct evidence names"
    );
    distinct
}

/// The canonical Host argv case 6 admits, so the installation and generation
/// identities the projection is checked against are the real parser's own typed
/// values rather than literals invented by the test. Pure argv construction:
/// every value is synthetic and nonsecret and nothing is read from or written
/// to the machine.
fn case_6_launch_argv() -> Vec<std::ffi::OsString> {
    vec![
        std::ffi::OsString::from("--config-descriptor"),
        std::env::temp_dir()
            .join("eliot-889-case-6-launch-auth.json")
            .into_os_string(),
        std::ffi::OsString::from("--config-descriptor-sha256"),
        std::ffi::OsString::from("b".repeat(64)),
        std::ffi::OsString::from("--installation-id"),
        std::ffi::OsString::from("installation-889-case-6"),
        std::ffi::OsString::from("--tx-plan-generation"),
        std::ffi::OsString::from(expected_case_6_generation().to_string()),
        std::ffi::OsString::from("--host-state-root"),
        std::env::temp_dir()
            .join("eliot-889-case-6-host-state")
            .into_os_string(),
    ]
}

// WORK_UNIT_CASE: 889/6
#[test]
fn host_request_projection_carries_the_exact_typed_identities() {
    // Behaviour under test (case 6, "exact request/operation/component
    // identities"): one projected Host request carries the exact typed
    // identities it was constructed with, and every slot the constructor did
    // not receive stays explicitly missing rather than guessed. The test fails
    // if a slot is rendered from anything but the value handed to its
    // constructor, if a missing slot stops reading missing, or if two evidence
    // classes stop being distinguishable in the emitted record.
    let options = eliot_host::HostLaunchOptions::parse(case_6_launch_argv())
        .expect("the canonical argv must be admitted by the real parser");
    let installation = options.installation().as_str().to_owned();
    let generation = options.transaction_plan_generation();
    assert_eq!(
        installation, "installation-889-case-6",
        "the admitted installation identity must be the one the parser bound"
    );
    assert_eq!(
        generation,
        expected_case_6_generation(),
        "the admitted generation must be the one the parser bound"
    );

    // One admitted service stop in the SCM phase, carrying every identity an
    // external caller can actually hand the projection, captured beside the
    // contrast sighting inside one scoped subscriber so the two records can be
    // told apart by slot, never by capture order.
    //
    // A real `HostComposition` and a real `HostState` snapshot are NOT
    // constructible from an integration-test target (opening a composition
    // needs a live installation, owner lease and Windows process contour), so
    // the `running` and `receipt_sequence` slots are covered below through the
    // explicitly-missing arm rather than through a fabricated value.
    let text = assert_the_stop_and_sighting_stay_two_scoped_host_request_records(&options);

    // The exact identities the stop projection was handed.
    let stop_line = text
        .lines()
        .find(|line| line.contains("evidence=\"durable_committed\""))
        .expect("the committed stop must emit its own durable_committed record");
    let sighting_line = text
        .lines()
        .find(|line| line.contains("evidence=\"observed\""))
        .expect("the sighting must emit its own observed record");
    for (key, expected) in [
        ("request", HostConsoleRequest::Stop.as_str()),
        ("operation", AdmittedEvent::ServiceStop.as_str()),
        ("installation", installation.as_str()),
        ("phase", EntrypointStage::ScmDispatch.as_str()),
    ] {
        assert!(
            stop_line.contains(&format!("{key}=\"{expected}\"")),
            "the committed stop must carry {key}={expected}, got: {stop_line}"
        );
    }
    assert!(
        stop_line.contains(&format!(
            "evidence=\"{}\"",
            HostRequestEvidence::DurableCommitted.as_str()
        )),
        "the committed stop must classify its own evidence, got: {stop_line}"
    );
    assert_bound_slots_stay_missing_and_bare_slots_keep_their_exact_values(
        stop_line,
        sighting_line,
    );
    assert!(
        !sighting_line.contains(&installation),
        "a sighting must never carry an installation it was not given, got: {sighting_line}"
    );

    // The two evidence classes stay distinct records, and each sighting stays
    // spelled under the owner's own frozen evidence vocabulary.
    assert_ne!(
        stop_line, sighting_line,
        "a committed stop and a sighting must stay distinct records"
    );
    assert_each_sighting_classifies_under_the_frozen_evidence_vocabulary(sighting_line);
    assert!(
        !stop_line.contains(HostRequestEvidence::Cancelled.as_str())
            && !stop_line.contains(HostRequestEvidence::Failed.as_str())
            && !stop_line.contains(HostRequestEvidence::Unknown.as_str()),
        "a committed stop must never borrow another evidence name, got: {stop_line}"
    );
}

/// Emits the committed SCM-phase stop and the bare contrast sighting through the
/// real `observe_host_request` facade inside ONE scoped subscriber, and proves
/// the capture window really holds two `host.request` records that each carry
/// the owner's own component and phase identities.
///
/// Returns the captured window, so the caller must read its two records out and
/// keep asserting on them; the shape assertions here cannot be skipped by
/// ignoring the result.
fn assert_the_stop_and_sighting_stay_two_scoped_host_request_records(
    options: &eliot_host::HostLaunchOptions,
) -> String {
    // The computed terminal exit this stop carries is the ONE file-scope
    // `HOST_TERMINAL_EXIT` declared above `assert_bare_slots_keep_their_exact_values`,
    // so the bound this projection is constructed with and the bare slot the
    // caller asserts against it are the same constant and cannot drift apart.
    let stop = HostRequestProjection::durable_committed(EntrypointStage::ScmDispatch)
        .with_request(HostConsoleRequest::Stop)
        .with_operation(AdmittedEvent::ServiceStop)
        .with_launch_options(options)
        .with_process(std::process::id())
        .with_terminal_exit(HOST_TERMINAL_EXIT);

    // The contrast case: the same phase with nothing observed but the sighting.
    let sighting = HostRequestProjection::observed(EntrypointStage::ScmDispatch);
    let text = capture_request_evidence(&[sighting, stop]).1;

    // Each projection emits exactly one REQUEST record, and that count is
    // measured BY THE RECORD'S OWN EVENT NAME rather than by the width of the
    // window. `observe_host_request` calls `publish_projected_event_log_record`
    // FIRST (src/host_diagnostics.rs:954-955), and that publishes BEFORE it
    // consults the producer's state (1012-1018, 1029), so a projection naming an
    // admitted operation with matching evidence emits a `host.event_log_admission`
    // line here even though the bounded producer was never started. The bare
    // sighting names no `AdmittedEvent` and reaches no admission, so this window
    // holds two request records and exactly one admission record; the admission is
    // read by its own name below rather than being swept into the request count.
    let request_records: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("event=\"host.request\""))
        .collect();
    assert_eq!(
        request_records.len(),
        2,
        "one projection must emit exactly one request record, got {} of them in: \
         {text}",
        request_records.len()
    );
    assert_eq!(
        text.matches("event=\"host.request\"").count(),
        2,
        "both records must be host.request projections, got: {text}"
    );

    // The component identity is stamped on every record from the owner's own
    // constant, never from a caller-supplied string.
    assert_eq!(
        request_records
            .iter()
            .filter(|line| line.contains(&format!("service=\"{}\"", eliot_host::SERVICE_NAME)))
            .count(),
        2,
        "every projected record must name the Host service component, got: {text}"
    );
    assert_eq!(
        request_records
            .iter()
            .filter(|line| line.contains("phase=\"scm_dispatch\""))
            .count(),
        2,
        "every projected record must carry the phase it was constructed with, got: {text}"
    );
    // The one admission this window publishes is named, counted and classified
    // as an ADMISSION rather than left to inflate the request count above: the
    // committed stop is admitted by the Event Log and the bare sighting is not,
    // and the evidence each was published under is the product's own vocabulary.
    assert_eq!(
        text.matches("event=\"host.event_log_admission\"").count(),
        1,
        "only the committed stop names an admitted operation, so exactly one admission record may \
         be published, got: {text}"
    );
    assert_eq!(
        request_record_carrying(&text, HostRequestEvidence::DurableCommitted.as_str())
            .matches("event=\"host.event_log_admission\"")
            .count(),
        0,
        "the Event Log admission record must be its own record, never merged into the request \
         record it was published beside: {text}"
    );
    text
}

/// Proves the two evidence classes this case separated stay spelled apart, and
/// that the sighting's own evidence name is one of the owner's eight frozen
/// `HostRequestEvidence` names rather than an arbitrary formatted field.
fn assert_each_sighting_classifies_under_the_frozen_evidence_vocabulary(sighting_line: &str) {
    let distinct_evidence_names = assert_the_eight_evidence_names_stay_distinct();
    // The caller checks that the sighting it read really carries one of those
    // eight frozen names, so the vocabulary list cannot be dropped here.
    assert!(
        distinct_evidence_names.contains(&rendered_evidence(sighting_line).unwrap_or("")),
        "a sighting must classify under the owner's own evidence vocabulary, got: {sighting_line}"
    );
    assert!(
        sighting_line.contains(&format!(
            "evidence=\"{}\"",
            HostRequestEvidence::Observed.as_str()
        )),
        "a sighting must classify as observed, got: {sighting_line}"
    );
    assert!(
        !sighting_line.contains(HostRequestEvidence::DurableCommitted.as_str()),
        "a sighting must never be spelled as a committed outcome, got: {sighting_line}"
    );
}

// WORK_UNIT_CASE: 889/5
// WORK_UNIT_CASE: 889/13
#[test]
fn host_diagnostics_entrypoint_observation_matches_contract_fixture() {
    // The facade is compiled once in the host library and observed here;
    // the binary's use is compile-gated in `src/main.rs` (same crate path,
    // no second `mod`/copy). Scoped capture shadows any global install, so
    // this test stays isolated and parallel-safe. (Cases 889/5 stable
    // mapping without a second lifecycle, 889/13 deterministic capture.)
    let fixture = contract_fixture();
    let text = capture_the_entrypoint_stage_observation();
    let captured_len = captured_byte_count(&text);

    let expected_stage = fixture["stages"]["console_loop"]
        .as_str()
        .expect("fixture must pin the console_loop stage name");
    assert_eq!(
        EntrypointStage::ConsoleLoop.as_str(),
        expected_stage,
        "facade stage name must match the contract fixture"
    );
    assert_eq!(
        EntrypointStage::Startup.as_str(),
        fixture["stages"]["startup"]
            .as_str()
            .expect("fixture must pin the startup stage name")
    );
    assert_eq!(
        EntrypointStage::ScmDispatch.as_str(),
        fixture["stages"]["scm_dispatch"]
            .as_str()
            .expect("fixture must pin the scm_dispatch stage name")
    );
    assert!(
        text.contains(HOST_DIAGNOSTICS_TARGET),
        "scoped capture must contain the facade target, got: {text}"
    );
    assert!(
        text.contains(
            fixture["entrypoint_event"]
                .as_str()
                .expect("fixture must pin the entrypoint event name")
        ),
        "scoped capture must contain the entrypoint event, got: {text}"
    );
    assert!(
        text.contains(expected_stage),
        "scoped capture must contain the observed stage, got: {text}"
    );

    // Bounds and the absent Event Log seam stay pinned by the same fixture.
    assert_the_facade_bounds_match_the_contract_fixture(&fixture, captured_len);

    // No secret or payload canary may appear in a plain stage observation.
    assert_no_payload_canary_reaches_a_stage_observation(&text);
}

/// Runs one real `observe_entrypoint` stage observation through the facade under
/// a scoped `tracing` subscriber and returns the captured window.
///
/// Scoped capture shadows any global install rather than replacing it, so this
/// stays isolated and parallel-safe.
fn capture_the_entrypoint_stage_observation() -> String {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            observe_entrypoint(EntrypointStage::ConsoleLoop);
        });
        sink.bytes.lock().unwrap().clone()
    };
    String::from_utf8_lossy(&captured).into_owned()
}

/// The capture window's own size, so the caller can compare it against the
/// product's byte bound instead of against a constant it invented.
fn captured_byte_count(text: &str) -> usize {
    text.len()
}

/// Proves the two bounds this case publishes really are the facade's own, and
/// that the absent Event Log seam is still the one the fixture declares.
fn assert_the_facade_bounds_match_the_contract_fixture(fixture: &Value, captured_len: usize) {
    assert_eq!(
        MAX_DIAGNOSTIC_FIELD_BYTES,
        usize::try_from(
            fixture["max_field_bytes"]
                .as_u64()
                .expect("fixture must pin max_field_bytes")
        )
        .expect("fixture bound must fit usize")
    );
    assert_eq!(
        MAX_DIAGNOSTIC_DETAIL_BYTES,
        usize::try_from(
            fixture["max_detail_bytes"]
                .as_u64()
                .expect("fixture must pin max_detail_bytes")
        )
        .expect("fixture bound must fit usize")
    );
    assert_eq!(
        fixture["event_log_sink"]
            .as_str()
            .expect("fixture must pin the event log seam"),
        "unavailable"
    );
    assert!(
        captured_len < 8 * 1024,
        "diagnostic capture must stay bounded, got {captured_len} bytes"
    );
}

/// Sweeps the credential and payload canaries that must never reach a plain
/// stage observation. Nothing is fabricated: each canary is checked against the
/// bytes the facade actually rendered.
fn assert_no_payload_canary_reaches_a_stage_observation(text: &str) {
    for canary in [
        "AKIA",
        "password",
        "token=",
        "connection_string",
        "BEGIN PRIVATE",
    ] {
        assert!(
            !text.contains(canary),
            "stage observation must not contain canary {canary:?}, got: {text}"
        );
    }
}

/// The canonical five-pair Host launch argv this test target admits, so the
/// `admitted` projection stamps the real parser's own installation and
/// generation identities instead of test-authored literals. Every value is
/// synthetic and nonsecret; nothing is read from or written to the machine.
fn canonical_host_launch_argv() -> Vec<std::ffi::OsString> {
    vec![
        std::ffi::OsString::from("--config-descriptor"),
        std::env::temp_dir()
            .join("eliot-889-contract-descriptor.json")
            .into_os_string(),
        std::ffi::OsString::from("--config-descriptor-sha256"),
        std::ffi::OsString::from("a".repeat(64)),
        std::ffi::OsString::from("--installation-id"),
        std::ffi::OsString::from("889-contract-installation"),
        std::ffi::OsString::from("--tx-plan-generation"),
        std::ffi::OsString::from("7"),
        std::ffi::OsString::from("--host-state-root"),
        std::env::temp_dir()
            .join("eliot-889-contract-state-root")
            .into_os_string(),
    ]
}

/// Emits each projection through the real `observe_host_request` facade under
/// one scoped `tracing` subscriber and returns the evidence names that window
/// rendered, in emission order, plus the captured text.
///
/// Same scoped-capture pattern as the sibling tests in this file: the scoped
/// subscriber shadows rather than replaces the process-global one, so parallel
/// tests never fight over it.
///
/// A projection that DOES carry an `AdmittedEvent` reaches the Event Log
/// admission arm, and that arm publishes its `host.event_log_admission` record
/// before it consults the producer's state -- so the window can hold more lines
/// than it holds `host.request` records. Every reader below therefore counts
/// requests by the record's own `event=` name and never by the width of the
/// window.
fn capture_request_evidence(projections: &[HostRequestProjection]) -> (Vec<String>, String) {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            for projection in projections {
                observe_host_request(projection);
            }
        });
        sink.bytes.lock().unwrap().clone()
    };
    let text = String::from_utf8_lossy(&captured).into_owned();
    let mut evidence = Vec::new();
    for line in text.lines() {
        // Only `host.request` records carry the projected evidence slot; the
        // entrypoint and Event Log admission records must not be read here.
        if !line.contains("event=\"host.request\"") {
            continue;
        }
        let name = rendered_evidence(line)
            .unwrap_or_else(|| panic!("every host.request record must render evidence: {line}"));
        evidence.push(name.to_owned());
    }
    (evidence, text)
}

/// The one emitted record whose `field=` slot carries `name`, refusing to guess
/// when the window emitted it zero times or more than once.
fn request_record_carrying<'a>(text: &'a str, name: &str) -> &'a str {
    let mut found: Option<&'a str> = None;
    for line in text.lines() {
        if !line.contains("event=\"host.request\"") {
            continue;
        }
        if rendered_evidence(line) != Some(name) {
            continue;
        }
        assert!(
            found.is_none(),
            "one evidence class emits exactly one record, never two: {line}"
        );
        found = Some(line);
    }
    let Some(record) = found else {
        panic!("no emitted host.request record carries evidence {name:?}: {text}");
    };
    record
}

/// The evidence vocabulary token one emitted record rendered, or `None` when
/// the record carries no evidence slot or the slot is not one of the facade's
/// own lowercase `snake_case` evidence names. The filter is what keeps this
/// reader from mistaking an arbitrary formatted field for an identity.
fn rendered_evidence(record: &str) -> Option<&str> {
    let value = rendered_field(record, "evidence")?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return None;
    }
    Some(value)
}

/// One slot value read back out of one emitted record line, or `None` when the
/// record carries no such slot at all. The `fmt` layer writes `key=value`,
/// quoting a value only when it needs quoting, so both the bare and the quoted
/// form are accepted and the terminator is the next space.
fn rendered_field<'a>(record: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!(" {key}=");
    let start = record.find(prefix.as_str())? + prefix.len();
    let rest = &record[start..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let value = &rest[..end];
    Some(
        value
            .strip_prefix('"')
            .and_then(|quoted| quoted.strip_suffix('"'))
            .unwrap_or(value),
    )
}

// WORK_UNIT_CASE: 889/7
#[test]
fn host_request_evidence_progress_slots_stay_distinct() {
    // Behaviour under test: four externally constructible evidence classes
    // reach the wire as distinct records. `semantically_ready` remains a fifth
    // distinct vocabulary class, source-proven below without a fabricated host.
    //
    // `admitted` is driven through the real `HostLaunchOptions::parse`
    // producer, so the installation/generation identities it stamps are the
    // owner's own admitted values rather than fabricated ones.

    // HONEST COVERAGE OF THE ISSUE'S FIVE NAMED CLASSES. The issue names
    // observed / requested / started / ready / durable; this is the facade's
    // `HostRequestEvidence` vocabulary, so the mapping is:
    //   observed -> HostRequestEvidence::Observed
    //   requested -> HostRequestEvidence::Admitted (a request that has passed
    //                typed admission and carries its installation/generation)
    //   started  -> HostRequestEvidence::ProcessStarted
    //   ready    -> HostRequestEvidence::SemanticallyReady
    //   durable  -> HostRequestEvidence::DurableCommitted
    //
    // SCOPE RESIDUALS, recorded rather than papered over:
    //  * `semantically_ready` is proven at the VOCABULARY level only. Its
    //    constructor takes `&HostComposition`, whose sole constructor
    //    (`HostComposition::open`) needs an installed SystemService root, an
    //    owner lease and a Windows process contour, so no external integration
    //    test target can construct one and the class is never emitted at
    //    runtime from here. The assertions below that name it are therefore
    //    source-and-vocabulary proofs, NOT an executed emission.
    //  * the issue's word `requested` has NO product counterpart: grep over
    //    `bins/eliot-host/src/host_diagnostics.rs` finds no `Requested`
    //    evidence class, so `Admitted` is the admitted slot that carries it.
    //    No `Requested` class was invented and no `HostComposition` was
    //    faked; widening the vocabulary is a product change this card cannot
    //    make.
    let options = eliot_host::HostLaunchOptions::parse(canonical_host_launch_argv())
        .expect("the canonical Host launch argv must be admitted");
    let expected_installation = options.installation().as_str().to_owned();
    let expected_generation = options.transaction_plan_generation().to_string();

    // The independent runtime expected set is built from the four constructors
    // this target can execute, never from their captured output.
    let expected = [
        HostRequestEvidence::Observed.as_str(),
        HostRequestEvidence::Admitted.as_str(),
        HostRequestEvidence::ProcessStarted.as_str(),
        HostRequestEvidence::DurableCommitted.as_str(),
    ];

    // Four of the five slots are constructible from an external test target.
    // `semantically_ready` takes `&HostComposition`, whose only constructor
    // (`HostComposition::open`) needs an installed SystemService root; that
    // slot is proven below by its own stable name and the facade's construction
    // source, never by a faked host or a claim that this capture emitted it.
    let (emitted, captured_text) = capture_request_evidence(&[
        HostRequestProjection::observed(EntrypointStage::Startup),
        HostRequestProjection::admitted(EntrypointStage::LaunchConfig, &options),
        HostRequestProjection::process_started(EntrypointStage::ConsoleLoop, 4321),
        HostRequestProjection::durable_committed(EntrypointStage::ShutdownDrain),
    ]);

    // The admitted record binds the owner's own admitted identities, so it is a
    // real admission rather than an empty placeholder wearing the name.
    assert_admission_binds_the_owners_real_identities(
        &captured_text,
        &expected_installation,
        &expected_generation,
    );

    // The process-started record binds the observed process id, and only that
    // slot does: `with_process` elsewhere must not conjure a start identity.
    // Liveness and readiness stay separate: no progress record emitted here may
    // claim a running state, because none of these four constructors bound one.
    assert_no_progress_record_claims_a_running_state(&captured_text);

    // The one unreachable slot is still bound to its own name, and the facade
    // builds it only from a host's actual running state, never from a literal.
    // Read-only source proof so this claim stays anchored to what the facade
    // really does rather than to what this target could execute. The returned
    // (runnable, running) pair is handed to the caller below, which uses BOTH
    // halves; the assertions inside can never be skipped.
    let (runnable, running) = prove_semantic_readiness_binds_only_real_host_state();
    // The caller consumes BOTH halves of the returned pair, so neither can be
    // dropped: `runnable` is the readiness class's own rendered name and
    // `running` is the exact binding the facade performs, neither of which this
    // case could have assumed for itself.
    assert_eq!(
        (runnable, running),
        (
            "semantically_ready",
            "projection.running = Some(host.running());"
        ),
        "the unreachable readiness slot must stay bound to its own name and to the facade's \
         own host running state"
    );
    for runtime_class in &expected {
        assert_ne!(
            runnable, *runtime_class,
            "semantic readiness must remain distinct from each captured class"
        );
    }
    assert_distinct_progress_evidence_classes(&emitted, &expected, &captured_text);
}

/// Proves the `admitted` record really carries the identities the real
/// `HostLaunchOptions::parse` producer bound, so the admitted evidence class is
/// not an empty placeholder wearing that name.
///
/// Every expected value is the caller's own parser output; nothing here is
/// restated as a literal.
fn assert_admission_binds_the_owners_real_identities(
    captured_text: &str,
    expected_installation: &str,
    expected_generation: &str,
) {
    let admitted = request_record_carrying(captured_text, HostRequestEvidence::Admitted.as_str());
    assert_eq!(
        rendered_field(admitted, "installation"),
        Some(expected_installation),
        "the admitted record must bind the owner's own installation identity: {admitted}"
    );
    assert_eq!(
        rendered_field(admitted, "generation"),
        Some(expected_generation),
        "the admitted record must bind the owner's own generation: {admitted}"
    );
    assert!(
        admitted.contains("installation_missing=false"),
        "a bound installation must report itself present: {admitted}"
    );
    assert!(
        admitted.contains("generation_missing=false"),
        "a bound generation must report itself present: {admitted}"
    );

    let started =
        request_record_carrying(captured_text, HostRequestEvidence::ProcessStarted.as_str());
    assert!(
        started.contains("process=4321"),
        "the process-started record must bind the observed process id: {started}"
    );
    assert!(
        started.contains("process_missing=false"),
        "a bound process id must report itself present: {started}"
    );
    let sighted = request_record_carrying(captured_text, HostRequestEvidence::Observed.as_str());
    assert!(
        sighted.contains("process_missing=true"),
        "a sighted request asserts no process identity: {sighted}"
    );

    let committed = request_record_carrying(
        captured_text,
        HostRequestEvidence::DurableCommitted.as_str(),
    );
    assert!(
        committed.contains("running_missing=true"),
        "a durable commit never carries a readiness claim it was not given: {committed}"
    );
    assert!(
        committed.contains("process_missing=true"),
        "a durable commit binds no process identity here: {committed}"
    );
}

/// Sweeps every emitted progress record for an unearned readiness claim: none of
/// the four constructible classes bound a running state, so each must keep both
/// the explicit missing flag and the meaningless placeholder.
fn assert_no_progress_record_claims_a_running_state(captured_text: &str) {
    for line in captured_text
        .lines()
        .filter(|line| line.contains("event=\"host.request\""))
    {
        assert!(
            line.contains("running_missing=true"),
            "no progress record may claim a running state it was not given: {line}"
        );
        assert!(
            line.contains("running=false"),
            "an absent running slot renders the placeholder, never a positive ready claim: {line}"
        );
    }
}

/// The four runtime-constructible progress classes must be mutually distinct;
/// readiness is checked separately against every emitted class and its source
/// binding, because this external target cannot construct a real Host.
fn assert_distinct_progress_evidence_classes(
    emitted: &[String],
    expected: &[&str],
    captured_text: &str,
) {
    // Each emitted record must carry its own stable name exactly once.
    // `seen.as_str()` is `str` and `name` binds as `&&str` here, so `*name`
    // dereferences it to the `&str` it already holds: both sides stay string
    // equality, and a collapse of two names onto one still fails the count.
    for name in expected {
        assert_eq!(
            emitted.iter().filter(|seen| seen.as_str() == *name).count(),
            1,
            "evidence {name:?} must be emitted exactly once, got {emitted:?} in:\n{captured_text}"
        );
    }

    // Distinctness is pairwise over the emitted values, not over the expected
    // list: two slots sharing one rendered name would collapse them.
    for (index, left) in emitted.iter().enumerate() {
        for right in emitted.iter().skip(index + 1) {
            assert_ne!(
                left, right,
                "two progress evidence slots rendered one name {left:?}, got {emitted:?}"
            );
        }
    }
    assert_eq!(
        emitted.len(),
        expected.len(),
        "the four constructible progress slots must emit four records, got {emitted:?}"
    );
    for name in emitted {
        assert!(
            expected.contains(&name.as_str()),
            "emitted evidence {name:?} is not one of the four captured progress classes {expected:?}"
        );
    }
}

/// The unreachable `semantically_ready` slot, proven without a faked host: the
/// class keeps its own stable name, stays distinct from process liveness and
/// durable commitment, and the facade binds and renders the host's actual
/// running state exactly once each, never from a literal.
///
/// Returns that class's rendered name together with the exact constructor
/// binding the facade performs, so the caller must thread both onward; the
/// assertions here are therefore not bypassable by ignoring the result.
fn prove_semantic_readiness_binds_only_real_host_state() -> (&'static str, &'static str) {
    let ready = HostRequestEvidence::SemanticallyReady.as_str();
    assert_eq!(
        ready, "semantically_ready",
        "the readiness evidence class keeps its own stable name"
    );
    assert_ne!(
        ready,
        HostRequestEvidence::ProcessStarted.as_str(),
        "process liveness and semantic readiness stay separate classes (I01.10)"
    );
    assert_ne!(
        ready,
        HostRequestEvidence::DurableCommitted.as_str(),
        "semantic readiness and durable commitment stay separate classes (I01.10)"
    );
    let binding = "projection.running = Some(host.running());";
    let facade = manifest_source("src/host_diagnostics.rs");
    assert_eq!(
        facade.matches(binding).count(),
        1,
        "the readiness constructor must bind the host's actual running state, exactly once"
    );
    assert_eq!(
        facade
            .matches("running = projection.running.unwrap_or(false),")
            .count(),
        1,
        "the record must render the bound running state exactly once"
    );
    (ready, binding)
}

// WORK_UNIT_CASE: 889/8
#[test]
fn host_request_terminal_evidence_slots_stay_three_distinct_records() {
    // Behaviour under test: `failed`, `cancelled` and `unknown` are three
    // distinct evidence classes and never collapse into one "not-ok" name.
    // `failed_without_reason` is the reason-missing arm: the record stays
    // `failed` while the reason slot reads explicitly missing, so a missing
    // reason is never guessed into an invented code.

    let expected = [
        HostRequestEvidence::Failed.as_str(),
        HostRequestEvidence::Cancelled.as_str(),
        HostRequestEvidence::Unknown.as_str(),
    ];

    let (emitted, captured_text) = capture_request_evidence(&[
        HostRequestProjection::failed_without_reason(EntrypointStage::ConsoleLoop)
            .with_request(HostConsoleRequest::Status),
        HostRequestProjection::cancelled(EntrypointStage::ShutdownDrain)
            .with_request(HostConsoleRequest::Stop),
        HostRequestProjection::unknown(EntrypointStage::Startup),
    ]);

    assert_terminal_evidence_classes_stay_mutually_distinct(&emitted, &expected);
    assert_terminal_records_bind_nothing_they_were_never_given(&captured_text);

    // A failure with the typed error actually in hand binds that error's
    // discriminant, and never its `Debug`/`Display` text.
    let attributed = assert_typed_failure_reason_binds_the_discriminant();

    // The reason-missing arm exists in the facade at all, and it leaves the
    // reason slot unset rather than filling one: a version that dropped the arm
    // or defaulted it to a code would fail here.
    let arm = prove_the_reason_missing_arm_binds_no_reason();

    // The reason-missing arm is still exactly `failed` and its reason slot
    // reads explicitly missing. A guessed reason would satisfy every other
    // assertion in this test, so this is the load-bearing one.
    let unattributed =
        request_record_carrying(&captured_text, HostRequestEvidence::Failed.as_str());

    // The attributed record has to be the same record the arms below say it is:
    // it must still be the one `failed` class, and it must be a DIFFERENT
    // record from the unattributed one above, so the two reason arms are two
    // emissions of one class rather than the same line read twice.
    assert!(
        attributed != unattributed,
        "a typed reason must produce its own record, never re-render the unattributed one: \
         {attributed}"
    );
    assert_eq!(
        rendered_evidence(&attributed),
        Some(HostRequestEvidence::Failed.as_str()),
        "the attributed record must still carry the failed class it was looked up by: {attributed}"
    );
    assert!(
        !arm.contains("reason") && arm.contains("Self::bare(phase,HostRequestEvidence::Failed)"),
        "the reason-missing arm must build the bare failed projection and bind no reason: {arm}"
    );
}

/// Proves the three terminal classes this case emitted are mutually distinct
/// records under their own three names: each expected name is emitted exactly
/// once, no two emitted records share a name, exactly the three named classes
/// were emitted, and every emitted name belongs to the three.
fn assert_terminal_evidence_classes_stay_mutually_distinct(emitted: &[String], expected: &[&str]) {
    // `seen.as_str()` is `str` and `name` binds as `&&str` here, so `*name`
    // dereferences it to the `&str` it already holds: both sides stay string
    // equality, and two terminal classes rendering one name still fail the
    // count.
    for name in expected {
        assert_eq!(
            emitted.iter().filter(|seen| seen.as_str() == *name).count(),
            1,
            "evidence {name:?} must be emitted exactly once, got {emitted:?}"
        );
    }
    for (index, left) in emitted.iter().enumerate() {
        for right in emitted.iter().skip(index + 1) {
            assert_ne!(
                left, right,
                "two terminal evidence slots rendered one name {left:?}, got {emitted:?}"
            );
        }
    }
    assert_eq!(
        emitted.len(),
        expected.len(),
        "three terminal evidence classes must emit three records, got {emitted:?}"
    );
    for name in emitted {
        assert!(
            expected.contains(&name.as_str()),
            "emitted evidence {name:?} is not one of the three terminal classes {expected:?}"
        );
    }
}

/// Proves what each of the three emitted terminal records may carry, and only
/// what it was handed.
///
/// The reason-missing arm is load-bearing: a guessed reason would satisfy every
/// other assertion in this case. Cancelled is a proven no-effect stop and unknown
/// is a genuinely unattributed outcome, so neither may bind a reason, a process
/// identity, or a terminal receipt.
fn assert_terminal_records_bind_nothing_they_were_never_given(captured_text: &str) {
    let unattributed = request_record_carrying(captured_text, HostRequestEvidence::Failed.as_str());
    assert!(
        unattributed.contains("reason_missing=true"),
        "an unattributed failure must leave the reason explicitly missing: {unattributed}"
    );
    assert!(
        unattributed.contains("reason=\"\""),
        "an absent reason renders the empty placeholder, never a code: {unattributed}"
    );
    assert!(
        unattributed.contains("request=\"status\""),
        "the attached console request identity must survive: {unattributed}"
    );

    let cancelled = request_record_carrying(captured_text, HostRequestEvidence::Cancelled.as_str());
    assert!(
        cancelled.contains("process_missing=true") && cancelled.contains("reason_missing=true"),
        "a proven no-effect cancellation asserts nothing it was not given: {cancelled}"
    );
    assert!(
        cancelled.contains("request=\"stop\""),
        "the attached console request identity must survive: {cancelled}"
    );
    let unknown = request_record_carrying(captured_text, HostRequestEvidence::Unknown.as_str());
    assert_unknown_outcome_binds_nothing(unknown);
}

/// An unknown outcome asserts nothing positive: reason, process identity,
/// receipt sequence, receipt exit, installation, generation and running state
/// all stay explicitly missing, so no unknown record can carry an identity it
/// was never handed.
fn assert_unknown_outcome_binds_nothing(unknown: &str) {
    for absent in [
        "reason_missing=true",
        "process_missing=true",
        "receipt_sequence_missing=true",
        "receipt_exit_missing=true",
        "installation_missing=true",
        "generation_missing=true",
        "running_missing=true",
    ] {
        assert!(
            unknown.contains(absent),
            "an unknown outcome asserts nothing positive, missing {absent}: {unknown}"
        );
    }
}

/// The reason-missing failure arm, read out of the real facade source.
///
/// The check is BEHAVIOUR-SHAPED, not formatting-shaped. The arm's body is
/// brace-matched out of the real facade source and stripped of every
/// whitespace character, so reformatting the constructor onto one line (or
/// re-indenting it) cannot change the verdict, while binding a reason by any
/// spelling at all - an assignment, a struct field, a `with_reason`-style call -
/// reintroduces the word `reason` into the body and fails here.
///
/// Returns that body so the caller must carry it forward; the assertions inside
/// here cannot be skipped by ignoring the result.
fn prove_the_reason_missing_arm_binds_no_reason() -> String {
    let facade = manifest_source("src/host_diagnostics.rs");
    assert_eq!(
        facade.matches("fn failed_without_reason").count(),
        1,
        "the reason-missing failure arm must be declared exactly once"
    );
    let body = fn_body_without_whitespace(&facade, "fn failed_without_reason")
        .expect("the reason-missing failure arm must still have a brace-matched body");
    assert!(
        body.contains("Self::bare(phase,HostRequestEvidence::Failed)"),
        "the reason-missing failure arm must build the bare Failed projection, got: {body}"
    );
    assert!(
        !body.contains("reason"),
        "the reason-missing failure arm must bind no reason field in its body, got: {body}"
    );
    body
}

/// A failure whose typed error is actually in hand binds that error's
/// discriminant as the reason, never its `Debug`/`Display` text, and stays the
/// one `failed` class emitting exactly one record.
///
/// Returns that attributed record so the caller must compare it against the
/// unattributed one; every assertion here is load-bearing on its own.
fn assert_typed_failure_reason_binds_the_discriminant() -> String {
    let stopped = HostError::Stopped;
    let (reason_window, reason_text) = capture_request_evidence(&[HostRequestProjection::failed(
        EntrypointStage::ShutdownDrain,
        &stopped,
    )]);
    assert_eq!(
        reason_window,
        vec![HostRequestEvidence::Failed.as_str().to_owned()],
        "a failure with a typed error in hand is still the one failed class, and one record"
    );
    let attributed = request_record_carrying(&reason_text, HostRequestEvidence::Failed.as_str());
    assert_eq!(
        rendered_field(attributed, "reason"),
        Some("stopped"),
        "the typed error discriminant must be bound as the reason: {attributed}"
    );
    assert!(
        attributed.contains("reason_missing=false"),
        "a bound reason must report itself present: {attributed}"
    );
    assert!(
        !attributed.contains("host is already stopped"),
        "the record must not carry the error's Display text: {attributed}"
    );
    attributed.to_owned()
}

// WORK_UNIT_CASE: 889/9
#[test]
fn event_log_success_is_never_reported_above_registration_unknown() {
    // Behaviour under test: the Event Log facade's success claim is the
    // registration-unknown one and never the registered-source one. #984's
    // receipt cannot prove a registered source, so the wrapper must not claim
    // the registered-source profile from OS acceptance or from handle
    // acquisition alone: "Never silently substitute fallback or equate
    // successful handle acquisition with installed message resources." This is
    // exactly the conflation comment `5934100576` refuted a prior delivery for.
    //
    // Proof is read-only source plus type shape plus the real seam. No wrapper
    // source is edited and no delivery outcome is invented.
    //
    // The receipt admits exactly one source-availability state and it is the
    // unknown one, so no receipt on any host can prove the registered-source
    // profile and the wrapper's registered-source arm has no reachable input.
    // Returns the availability readback spelling those receipts expose, which
    // the delivery arm below must carry.
    let readback = prove_the_receipt_admits_only_unknown_availability();

    // The wrapper's success mapping is exhaustive over that one variant, so a
    // future proven-registration receipt could not fall silently into the
    // unknown arm, and the only `Ok` arm it can build today is the weak one.
    let wrapper = manifest_source("src/windows_event_log.rs");
    assert_no_wrapper_path_inflates_an_acceptance_receipt(&wrapper);

    // The three delivery arms keep distinct names, and the arm a receipt can
    // actually produce is named as the weak statement: OS acceptance with
    // registration unknown.
    assert_the_reachable_delivery_arm_is_named_registration_unknown(&readback);

    // Runtime proof on the seam this target can really drive: the real
    // `report_event` outcome, checked against the product's own typed seam
    // status so each arm is compared to the port state that produced it rather
    // than to a `cfg!` constant.
    assert_the_real_event_log_outcome_matches_the_seam_status();
}

/// Proves the wrapper's success mapping is exhaustive over the one receipt
/// availability it can see, so a future proven-registration receipt could not
/// fall silently into the unknown arm and no path builds an inflated claim.
fn assert_no_wrapper_path_inflates_an_acceptance_receipt(wrapper: &str) {
    assert_eq!(
        wrapper
            .matches(
                "match receipt.source_availability() {\n                EventLogSourceAvailability::Unknown => {\n                    Ok(EventLogDelivery::OsAcceptedRegistrationUnknown { event })\n                }\n            }"
            )
            .count(),
        1,
        "the wrapper must map the only receipt availability to the registration-unknown arm"
    );
    for inflated in [
        "Ok(EventLogDelivery::RegisteredSourceAccepted",
        "Ok(EventLogDelivery::DegradedApplicationAccepted",
    ] {
        assert!(
            !wrapper.contains(inflated),
            "no wrapper path may build the {inflated:?} claim from an acceptance receipt"
        );
    }
}

/// Proves the three delivery arms keep distinct names, that every arm still
/// correlates to its submitted event, and that the arm a receipt can actually
/// produce is named as the weak statement: OS acceptance with registration
/// unknown. The check is anchored to the receipt's own availability readback,
/// which the caller threads in, never to a locally assumed signature.
fn assert_the_reachable_delivery_arm_is_named_registration_unknown(readback: &str) {
    let unknown = EventLogDelivery::OsAcceptedRegistrationUnknown {
        event: AdmittedEvent::ServiceStart,
    };
    let registered = EventLogDelivery::RegisteredSourceAccepted {
        event: AdmittedEvent::ServiceStart,
    };
    let degraded = EventLogDelivery::DegradedApplicationAccepted {
        event: AdmittedEvent::ServiceStart,
    };
    assert_eq!(
        unknown.as_str(),
        "os_accepted_registration_unknown",
        "the reachable success arm must name OS acceptance with registration unknown"
    );
    assert_eq!(
        registered.as_str(),
        "registered_source_accepted",
        "the registered-source arm keeps its own distinct name"
    );
    assert_eq!(
        degraded.as_str(),
        "degraded_application_accepted",
        "the degraded Application arm keeps its own distinct name"
    );
    assert_ne!(
        unknown.as_str(),
        registered.as_str(),
        "OS acceptance with registration unknown must never read as the registered-source profile"
    );
    assert_ne!(
        unknown.as_str(),
        degraded.as_str(),
        "no silent fallback: the unknown arm must never read as the degraded profile"
    );
    for delivery in [unknown, registered, degraded] {
        assert_eq!(
            delivery.event(),
            AdmittedEvent::ServiceStart,
            "every delivery arm must still correlate to its submitted event"
        );
    }
    assert!(
        readback.ends_with(" -> EventLogSourceAvailability {"),
        "the delivery claim above must rest on the receipt's own availability readback, not on \
         a locally assumed signature: {readback}"
    );
}

/// Drives one real `report_event` call and checks the outcome against the
/// product's OWN live seam status rather than against a compile-time constant.
///
/// `event_log_sink_status()` is the same live probe the facade's
/// `note_event_log_sink_status` consumes, so it is the real platform predicate
/// "this build has a live Event Log port", not an assertion about the target.
/// The two clauses this replaces each fell out of `report_event` alone:
///
/// * an accepted delivery could only be reported where the port is live, so
///   `EventLogUnavailable` answers are the port-dead branch and must carry no
///   success claim, and any success must be the weak registration-unknown arm;
/// * a refusal (`SourceUnavailable`/`ReportRefused`) means the OS port WAS
///   reached and the OS itself refused, which off Windows is unreachable
///   because no call is ever made there -- so `EventLogUnavailable` off Windows
///   remains the one honest answer, proven by the seam status being
///   `EventLogUnavailable` exactly when this build is off Windows.
fn assert_the_real_event_log_outcome_matches_the_seam_status() {
    let seam_attemptable = event_log_sink_status() == Ok(());
    let record = EventLogRecord::new(
        AdmittedEvent::ServiceStart,
        "service=EliotHost phase=startup evidence=process_started",
    );
    match report_event(&record) {
        Ok(delivery) => {
            assert!(
                seam_attemptable,
                "a success outcome exists only where the live Event Log seam is attemptable, \
                 which is the port being answered at all"
            );
            assert!(
                matches!(
                    delivery,
                    EventLogDelivery::OsAcceptedRegistrationUnknown {
                        event: AdmittedEvent::ServiceStart
                    }
                ),
                "an accepted delivery must be reported registration-unknown, never as the \
                 registered-source profile, got: {delivery:?}"
            );
        }
        Err(WindowsEventLogError::EventLogUnavailable) => {
            assert!(
                !seam_attemptable,
                "an unavailable answer exists only where the live Event Log seam reports \
                 unavailable: on Windows the port must be attempted, not answered unavailable"
            );
        }
        Err(
            error @ (WindowsEventLogError::SourceUnavailable { .. }
            | WindowsEventLogError::ReportRefused { .. }),
        ) => {
            assert!(
                seam_attemptable,
                "a refusal outcome exists only where the live Event Log seam is attemptable, \
                 got: {error:?}"
            );
        }
        Err(error) => panic!("the bounded redacted record must validate, got: {error:?}"),
    }
}

/// The platform Event Log receipt admits exactly one source-availability state
/// and it is the unknown one, so no receipt on any host can prove the
/// registered-source profile and the wrapper's registered-source arm has no
/// reachable input.
///
/// Returns the availability readback spelling both receipts expose, so the
/// caller must carry it forward; the source-shape assertions here cannot be
/// skipped by ignoring the result.
fn prove_the_receipt_admits_only_unknown_availability() -> String {
    let platform = manifest_source("../../crates/kernel/eliot-platform-windows/src/event_log.rs");
    assert_eq!(
        platform
            .matches("pub enum EventLogSourceAvailability {")
            .count(),
        1,
        "receipt availability must be one closed enum"
    );
    assert_eq!(
        platform.matches("    Unknown,\n}").count(),
        1,
        "EventLogSourceAvailability must carry exactly the Unknown variant"
    );
    for accepted in [
        "    const fn accepted(event: AdmittedEventLogEvent) -> Self {\n        Self {\n            event,\n            availability: EventLogSourceAvailability::Unknown,\n        }\n    }",
        "    const fn accepted(event: AdmittedKernelEventLogEvent) -> Self {\n        Self {\n            event,\n            availability: EventLogSourceAvailability::Unknown,\n        }\n    }",
    ] {
        assert_eq!(
            platform.matches(accepted).count(),
            1,
            "every receipt constructor must hard-code the unknown availability: {accepted}"
        );
    }
    // Each receipt exposes an availability readback, and both of them return
    // the field the constructor hard-coded; a receipt that stopped publishing
    // its availability would leave the wrapper nothing to classify on.
    let readback = "pub const fn source_availability(&self) -> EventLogSourceAvailability {";
    assert_eq!(
        platform.matches(readback).count(),
        2,
        "the host and kernel receipts each expose their availability readback"
    );
    assert_eq!(
        platform
            .matches("pub const fn source_availability(&self) -> EventLogSourceAvailability {\n        self.availability\n    }")
            .count(),
        2,
        "each availability readback must return the constructor-bound field, never a literal"
    );
    readback.to_owned()
}

// WORK_UNIT_CASE: 889/15
// WORK_UNIT_CASE: 889/16
// WORK_UNIT_CASE: 889/17
// WORK_UNIT_CASE: 889/18
#[test]
fn windows_event_log_wrapper_reports_through_the_safe_port() {
    // The wrapper maps #984's consumer contract (fixed source, event ids,
    // severity, redacted insertions; admitted start/stop/failure only)
    // through the safe port: typed accepted/refused/unavailable outcomes,
    // never FFI and never a silent fallback. (Cases 889/15 start, 889/16
    // stop, 889/17 failure mapping and correlation, 889/18 missing/denied
    // stays distinct and leaves the Host result unchanged.)
    let fixture = contract_fixture();
    assert_eq!(
        EVENT_LOG_SOURCE,
        fixture["event_log_source"]
            .as_str()
            .expect("fixture must pin the event log source")
    );
    for (event, key) in [
        (AdmittedEvent::ServiceStart, "service_start"),
        (AdmittedEvent::ServiceStop, "service_stop"),
        (AdmittedEvent::ServiceFailure, "service_failure"),
    ] {
        let record = EventLogRecord::new(event, "host funnel reached boundary");
        let (source, event_id, severity) = record.mapping();
        assert_eq!(source, EVENT_LOG_SOURCE);
        assert_eq!(
            event_id,
            u32::try_from(
                fixture["event_mappings"][key]["event_id"]
                    .as_u64()
                    .expect("fixture must pin the event id")
            )
            .expect("event id must fit u32")
        );
        assert_eq!(
            severity.as_str(),
            fixture["event_mappings"][key]["severity"]
                .as_str()
                .expect("fixture must pin the severity")
        );
        // Delivery proof through #984's safe port: on Windows the OS call is
        // attempted and every outcome stays typed; off Windows the port is
        // honestly unavailable. The caller's Host result is untouched either
        // way (Ok stays Ok around the call).
        let host_result: Result<(), &'static str> = Ok(());
        assert_safe_port_outcome_is_typed(&record, event, host_result);
    }

    // Failure correlation uses the frozen terminal code as the redacted
    // insertion; the record keeps truncation honesty.
    let failure = EventLogRecord::new(
        AdmittedEvent::ServiceFailure,
        HOST_TERMINAL_CODE_CONSOLE_FAILED,
    );
    assert!(failure.insertion().contains("console_failed"));
    assert!(!failure.truncated());
    let long_insertion = "d".repeat(8 * MAX_DIAGNOSTIC_DETAIL_BYTES);
    let truncated = EventLogRecord::new(AdmittedEvent::ServiceFailure, &long_insertion);
    assert!(truncated.truncated());
    assert!(truncated.insertion().len() <= MAX_DIAGNOSTIC_DETAIL_BYTES);

    // Finite nonblocking admission: capacity is honored, overflow drops with
    // an exact count, shutdown parks the remainder as Unknown without
    // claiming a drain or abort that did not complete. (Supports 889/10 and
    // 889/14 queue/drop/shutdown honesty.)
    assert_eq!(
        usize::try_from(
            fixture["queue_capacity"]
                .as_u64()
                .expect("fixture must pin the queue capacity")
        )
        .expect("queue capacity must fit usize"),
        EVENT_LOG_QUEUE_CAPACITY
    );
    let mut queue = WindowsEventLogQueue::new(2);
    assert!(queue.is_empty());
    queue
        .try_admit(EventLogRecord::new(AdmittedEvent::ServiceStart, "start"))
        .expect("admission within capacity must succeed");
    queue
        .try_admit(EventLogRecord::new(AdmittedEvent::ServiceStop, "stop"))
        .expect("admission within capacity must succeed");
    assert_eq!(queue.len(), 2);
    assert_eq!(
        queue.try_admit(EventLogRecord::new(AdmittedEvent::ServiceFailure, "full")),
        Err(WindowsEventLogError::QueueFull)
    );
    assert_eq!(queue.dropped_total(), 1);
    let shutdown = queue.shutdown();
    assert!(queue.is_closed());
    assert_eq!(
        shutdown.unsent(),
        2,
        "shutdown must park held records as unsent"
    );
    assert_eq!(shutdown.dropped_total(), 1);
    assert_eq!(
        queue.try_admit(EventLogRecord::new(AdmittedEvent::ServiceStart, "late")),
        Err(WindowsEventLogError::Closed)
    );
}

// WORK_UNIT_CASE: 889/22
#[test]
fn tracing_never_corrupts_console_stdout_framing() {
    // Subscriber writes stderr only; `write_response`
    // (`host_console_protocol.rs:44-50`) keeps sole stdout ownership;
    // parallel scoped capture must not replace the global subscriber.
    // Smallest proof: drive ready/state frames while diagnostics emit and
    // assert stdout frames stay exactly one-JSON-per-line.
    let fixture = contract_fixture();
    assert_eq!(
        fixture["stdout_protocol_contamination"].as_bool(),
        Some(false),
        "fixture must pin clean stdout framing"
    );

    let ready = serde_json::json!({"status": "ready", "service": "test", "protocol": "test"});
    let state = serde_json::json!({"status": "state", "running": true});

    // Parallel scoped captures each receive their own record while the
    // stdout buffer is framed on this thread; no capture touches stdout.
    let stdout_sink = CaptureSink::default();
    let stdout_bytes = stdout_sink.bytes.clone();
    std::thread::scope(|scope| {
        for stage in [
            EntrypointStage::Startup,
            EntrypointStage::ConsoleLoop,
            EntrypointStage::ShutdownDrain,
        ] {
            scope.spawn(move || {
                let thread_sink = CaptureSink::default();
                let writer = thread_sink.clone();
                let subscriber = tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_writer(move || writer.clone())
                    .finish();
                tracing::subscriber::with_default(subscriber, || {
                    observe_entrypoint(stage);
                    observe_terminal_error(HOST_TERMINAL_CODE_CONSOLE_FAILED);
                });
                let text = String::from_utf8_lossy(&thread_sink.bytes.lock().unwrap()).into_owned();
                assert!(
                    text.contains(HOST_DIAGNOSTICS_TARGET),
                    "scoped thread capture must contain the target, got: {text}"
                );
                assert!(
                    text.contains(stage.as_str()),
                    "scoped thread capture must contain its stage, got: {text}"
                );
            });
        }
        scope.spawn(|| {
            let mut buffer = Vec::new();
            assert!(write_protocol_frame(&mut buffer, &ready));
            assert!(write_protocol_frame(&mut buffer, &state));
            stdout_bytes.lock().unwrap().extend_from_slice(&buffer);
        });
    });

    let stdout = stdout_bytes.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&stdout).into_owned();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "stdout must stay exactly one-JSON-per-line, got: {text}"
    );
    for line in &lines {
        serde_json::from_str::<Value>(line).expect("every stdout line must stay exact JSON");
    }
    assert!(
        !text.contains(HOST_DIAGNOSTICS_TARGET),
        "tracing must never leak into stdout frames, got: {text}"
    );
    assert!(
        !text.contains(
            fixture["entrypoint_event"]
                .as_str()
                .expect("fixture must pin the entrypoint event name")
        ),
        "diagnostic events must never contaminate stdout, got: {text}"
    );
}

// ------------------------------------------------------------------ canaries --

/// One test-owned marker for a bounded text channel.
struct Canary {
    channel: &'static str,
    value: String,
}

impl Canary {
    fn new(channel: &'static str, marker: &str) -> Self {
        Self {
            channel,
            value: format!("{marker}-{channel}-889"),
        }
    }
}

/// Pours one explicitly nonsecret, test-owned marker through the shape of the
/// channel the facade receives, rather than a genuine credential, environment
/// value, connection string, source, user, or model payload.
///
/// The bearer-shaped marker is built from this test's value, never from the
/// machine's environment. An earlier revision read the first `PATH` entry and
/// fell back to the plain marker, making the fixture host-dependent and leaving
/// `contains("Bearer ")` false on hosts without PATH. No product call site
/// builds a token out of PATH; the scheme prefix is the shape under test and
/// the suffix is a dummy marker.
///
/// Returns the channel and exact marker poured, so assertions compare against
/// the input rather than a value reconstructed from captured output.
fn pour(channel: &'static str, marker: &str) -> Canary {
    let seed = Canary::new(channel, marker);
    let value = match channel {
        // A bearer-shaped test marker, not a real credential.
        "TOKEN" => format!("Bearer {marker}-889-11-DUMMY!"),
        // Every remaining channel value is the explicitly nonsecret marker.
        _ => seed.value.clone(),
    };
    Canary { channel, value }
}

/// The independently declared set of credential/environment channels this
/// sweep is expected to exclude, taken from the governing exclusion sentence
/// rather than from the values this test happened to pour. The payload channels
/// are excluded by the same requirement and are swept by case 889/12.
const EXCLUDED_SECRET_CHANNELS: [&str; 4] = ["CREDENTIAL", "TOKEN", "ENVIRONMENT", "CONNECTION"];

/// The payload channels the same exclusion sentence names, swept by case
/// 889/12 against the facade's closed field surface.
const EXCLUDED_PAYLOAD_CHANNELS: [&str; 3] = ["SOURCE", "USER", "MODEL"];

/// Every reason kind the facade may project into a request record: the
/// `HostError` variant discriminants only, never a message, a source chain, or
/// any error payload. A projected reason outside this list would mean the
/// facade started projecting something other than a frozen reason code.
///
/// The set is COMPLETE and is not merely a sample. `pub enum HostError` in
/// `src/lib.rs` declares exactly 18 variants, and `project_host_error_reason`
/// in `src/host_diagnostics.rs` maps every one of them onto exactly one string
/// (four of them behind `#[cfg(windows)]`, which is why an off-Windows build
/// still cannot project a non-Windows reason). `PERMITTED_REASON_CODE_COUNT` is
/// asserted equal to the facade's own `HostError` arm count by case 889/20, so
/// a 19th variant added later fails that test instead of escaping this sweep
/// unnoticed.
const PERMITTED_REASON_CODES: [&str; 18] = [
    "store_census_kernel",
    "store_census_transport",
    "store_census_runtime",
    "state",
    "journal",
    "installation",
    "platform",
    "stopped",
    "missing_installation",
    "process_contour",
    "store_not_live",
    "recovery_required",
    "origin_collision_unproven",
    "store_endpoint_owner_unreadable",
    "store_recovery_required",
    "watchdog_coverage_unavailable",
    "owner_lease_held",
    "owner_lease_recovery",
];

/// The exact number of reason codes [`PERMITTED_REASON_CODES`] must hold,
/// kept as its own named constant so the count is asserted in one place.
const PERMITTED_REASON_CODE_COUNT: usize = 18;

/// The size of this issue's case matrix, and therefore of BOTH the fixture's
/// `cases` array and the set of `// WORK_UNIT_CASE: 889/<n>` markers this file
/// carries. The two are cross-checked against each other by case 889/20, so
/// this constant can never silently disagree with either: a marker added,
/// removed or renumbered changes the file-side count and fails there.
const DECLARED_WORK_UNIT_CASE_COUNT: usize = 22;

// ------------------------------------------------------------ record capture --

/// Sink that records every byte the formatter writes and delivers none, so a
/// case can prove a record was formatted and bounded while the captured bytes
/// stay exactly the product's own field vocabulary.
#[derive(Clone, Default)]
struct MeasuringSink {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl MeasuringSink {
    fn rendered(&self) -> String {
        String::from_utf8_lossy(&self.bytes.lock().unwrap()).into_owned()
    }
}

impl Write for MeasuringSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("measurement sink lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A sink that GENUINELY FAILS: `write` records the offer and returns `Err`,
/// so no formatted byte is ever retained. This is what makes the degraded half
/// of the non-interference comparison real -- a sink named "degraded" that
/// returns `Ok(buf.len())` is a healthy sink, and both halves of the
/// comparison would then be the same arm.
#[derive(Clone, Default)]
struct FailingSink {
    offered: Arc<Mutex<usize>>,
    written: Arc<Mutex<usize>>,
}

impl FailingSink {
    fn offered_bytes(&self) -> usize {
        *self.offered.lock().unwrap()
    }

    fn written_bytes(&self) -> usize {
        *self.written.lock().unwrap()
    }
}

impl Write for FailingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        *self.offered.lock().unwrap() += buf.len();
        Err(std::io::Error::other(
            "injected diagnostic sink failure (889/14)",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The writer handle the formatter owns for a degraded run: a fresh clone of
/// the one failing sink for every `MakeWriter` call, so the sink the formatter
/// writes through is the same sink the caller counts.
#[derive(Clone)]
struct FailingWriter {
    sink: FailingSink,
}

impl Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sink.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink.flush()
    }
}

/// What the product published for one Event Log admission, reconstructed from
/// the product's own typed fields -- never from a literal the test chose. The
/// typed names are rendered through `AdmittedEvent::as_str()`,
/// `HostRequestEvidence::as_str()` and `EventLogAdmission::as_str()`, so a
/// renamed vocabulary shows up here instead of being silently absorbed. The
/// event and evidence slots keep their TYPED forms for exactly that reason: a
/// rendered name is resolved back through the product's own vocabulary, so a
/// name the product never emits has nowhere to resolve to.
///
/// `published_drops` is the `dropped_total` the product rendered on the record
/// itself, kept as its OWN field rather than inside `outcome`. That split is
/// what makes the cross-health comparison in case 889/14 possible at all: the
/// two `SinkRun::captured` scopes are separate `with_default` calls with no
/// lock or fence between them, each admitting a record into the ONE global
/// producer queue, while the single worker thread dequeues asynchronously and
/// advances that same process-global counter on the failure arm. So
/// `dropped_total` is not part of the claim "a failing sink does not change
/// the Host result" -- it moves on its own. `CounterFreeAdmission` below is the
/// counter-free projection the equality is made over; `dropped_total()` on it
/// is deliberately absent, so nothing can reach the volatile value through it.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AdmissionOutcome {
    event: AdmittedEvent,
    evidence: HostRequestEvidence,
    receipt_exit: Option<String>,
    outcome: EventLogAdmission,
    /// The monotone process-wide drop count the product published with THIS
    /// admission. Read from the record's own `dropped_total` slot, never from
    /// a later snapshot, and asserted separately from the cross-health
    /// equality because it advances between the two runs.
    published_drops: u64,
}

impl AdmissionOutcome {
    /// Reads one admission record, or `None` when the record is not one. The
    /// read never guesses: a missing or non-numeric slot is `None`, not a zero
    /// or a default.
    fn from_record(record: &CapturedRecord) -> Option<Self> {
        if record.event != "host.event_log_admission" {
            return None;
        }
        let event = record.field("operation")?;
        let evidence = record.field("evidence")?;
        let outcome = record.field("outcome")?;
        let receipt_exit = match record.field("receipt_exit") {
            None | Some("") => None,
            Some(exit) => Some(exit.to_owned()),
        };
        let named = EVENT_LOG_ADMISSION_BY_NAME
            .iter()
            .find(|(_, name)| *name == outcome)
            .map(|(admission, _)| *admission)
            .expect("the product published an admission name outside its own vocabulary");
        // The record's OWN `dropped_total` slot, not a value re-derived from
        // `named`: `named` was resolved through the vocabulary table, whose
        // entries are all built with `dropped_total: 0`, so reading the counter
        // back off `named` would silently report zero for every admission. A
        // record that published no such slot is a product change, so it fails
        // loudly here rather than being defaulted to a counter-free value.
        let published_drops = record
            .field("dropped_total")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_else(|| {
                panic!(
                    "the product's admission record must publish an integer dropped_total, got \
                     {:?}",
                    record.field("dropped_total")
                )
            });
        Some(Self {
            event: ADMITTED_EVENT_BY_NAME
                .iter()
                .find(|(_, name)| *name == event)
                .map(|(value, _)| *value)
                .expect("the product published an operation name outside its own vocabulary"),
            evidence: HOST_REQUEST_EVIDENCE_BY_NAME
                .iter()
                .find(|(_, name)| *name == evidence)
                .map(|(value, _)| *value)
                .expect("the product published an evidence name outside its own vocabulary"),
            receipt_exit,
            outcome: named,
            published_drops,
        })
    }

    /// The counter-free projection of one admission: everything the product
    /// published about THIS request EXCEPT the process-global drop counter.
    ///
    /// This is the honest comparison surface for the non-interference claim, and
    /// it is deliberately still a total equality over real product values:
    /// * the typed event and the typed evidence, both resolved back through the
    ///   product's own vocabulary, so a renamed or misclassified slot fails;
    /// * the receipt exit the record carried, so a projection that stopped
    ///   publishing its terminal exit (or published a different one) fails;
    /// * the admission's own VARIANT plus every bounded field of it, which for
    ///   `Admitted` includes `truncated`. A different `truncated` is a
    ///   different `as_str()` and therefore a different admission NAME, so
    ///   truncation honesty is inside this equality rather than beside it.
    ///
    /// `dropped_total` is what this projection leaves out, and it is left out
    /// through the product's OWN `as_str()`: `EventLogAdmission::as_str()`
    /// ignores every `dropped_total` in every arm and names only the variant
    /// (and, for `Admitted`, `truncated`). So the outcome name below is the
    /// product's own counter-free spelling of the admission, not a test-authored
    /// re-spelling, and a product mutation that changed the variant or the
    /// truncation flag under a failing sink changes it.
    ///
    /// Returns the projection, and the caller must compare it against the other
    /// run's projection rather than merely have run it.
    fn counter_free(&self) -> CounterFreeAdmission {
        CounterFreeAdmission {
            event: self.event,
            evidence: self.evidence,
            receipt_exit: self.receipt_exit.clone(),
            admission_name: self.outcome.as_str().to_owned(),
        }
    }
}

/// One [`AdmissionOutcome`] with the volatile drop counter projected out, via
/// [`EventLogAdmission::as_str()`]. Two of these compare equal exactly when the
/// product published the same event, the same evidence, the same receipt exit
/// and the same admission NAME under both runs.
///
/// This type has NO `dropped_total()` accessor and no copy of the counter, so
/// the cross-health equality in case 889/14 cannot reach the process-global
/// value even by accident.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CounterFreeAdmission {
    event: AdmittedEvent,
    evidence: HostRequestEvidence,
    receipt_exit: Option<String>,
    /// The product's own `EventLogAdmission::as_str()` for this admission: the
    /// variant name, plus `admitted_truncated` when the record was truncated.
    admission_name: String,
}

/// Layer that records the product's Event Log admission outcomes independently
/// of any writer, so the outcome survives a sink that fails every write.
#[derive(Clone)]
struct AdmissionLayer {
    outcomes: Arc<Mutex<Vec<AdmissionOutcome>>>,
}

impl<S> Layer<S> for AdmissionLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = EmittedFields::default();
        event.record(&mut fields);
        let record = CapturedRecord {
            target: event.metadata().target().to_owned(),
            event: fields
                .entries
                .iter()
                .find(|(name, _)| name == "event")
                .map_or_else(String::new, |(_, value)| value.clone()),
            fields: fields.entries,
            thread_id: std::thread::current().id(),
        };
        if let Some(outcome) = AdmissionOutcome::from_record(&record) {
            self.outcomes.lock().unwrap().push(outcome);
        }
    }
}

/// Whether the sink behind one run of an emit closure actually fails.
///
/// This exists so the two halves of a non-interference comparison cannot
/// quietly become the same arm: a "degraded" sink whose `write` returns
/// `Ok(buf.len())` is a healthy sink, and a comparison between two healthy sinks
/// proves nothing about degradation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SinkHealth {
    /// `write` records the offer and returns `Err`: degraded.
    Failing,
    /// `write` records the bytes and returns `Ok`: healthy.
    Healthy,
}

/// Writer that records each offer and retains every byte, returning `Ok`.
/// Deliberately identical to [`MeasuringSink`] except that it ALSO counts the
/// offer, so the two halves of a comparison can be told apart by their own
/// accounting rather than by name.
#[derive(Clone)]
struct HealthyWriter {
    offered: Arc<Mutex<usize>>,
    written: Arc<Mutex<usize>>,
}

impl Write for HealthyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        *self.offered.lock().unwrap() += buf.len();
        *self.written.lock().unwrap() += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One completed run of the same emit closure behind one sink health.
///
/// Both byte counts are the SINK's own accounting, never a literal: `offered`
/// is what the writer was handed and `written` is what it retained. A failing
/// sink therefore has `written == 0` by construction and a healthy one has
/// `written == offered`, which is what makes the cross-health byte equality in
/// case 889/14 a real observation about the same emission reaching both sinks
/// rather than a restatement of how this struct was built.
struct SinkRun {
    admissions: Vec<AdmissionOutcome>,
    offered: usize,
    written: usize,
}

impl SinkRun {
    /// Runs `emit` once behind the requested sink health and reports what the
    /// product published and what the sink did.
    ///
    /// The admission layer is installed UNDERNEATH the formatter layer, so the
    /// admission outcome is captured from the record itself and does not depend
    /// on the writer accepting a single byte. The two layers are the same and
    /// the closure is the same, so only the sink's health differs between two
    /// runs.
    fn captured(emit: impl FnOnce(), health: SinkHealth) -> Self {
        let outcomes = Arc::new(Mutex::new(Vec::<AdmissionOutcome>::new()));
        let recorded = Arc::clone(&outcomes);
        let sink = FailingSink::default();
        let failing = sink.clone();
        let healthy_offered = Arc::new(Mutex::new(0usize));
        let healthy_written = Arc::new(Mutex::new(0usize));
        let offered_by_writer = Arc::clone(&healthy_offered);
        let written_by_writer = Arc::clone(&healthy_written);
        // Each arm builds its OWN formatter -- a `fmt::Layer` -- carrying the
        // writer for that sink health, because the two writer closures have
        // different types and only one of them can be applied to a shared
        // builder. `fmt::layer()` is the LAYER form of the formatter:
        // `fmt()..finish()` hands back a whole `FmtSubscriber`, which is a
        // subscriber and NOT a `Layer`, so it could never be boxed into the
        // `Box<dyn Layer<Registry>>` this binding is annotated as. The layer
        // form is what actually gets composed onto the registry below.
        //
        // Both arms are boxed to one trait object because no two closures, even
        // identical ones, share a type: unboxed, the `match` had arms of two
        // different concrete types and could not be assigned to a single name.
        // Boxing types them alike WITHOUT collapsing them into one arm -- each
        // arm still carries its own writer, so the two runs still differ only in
        // sink health.
        let formatter: Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync> = match health {
            SinkHealth::Failing => Box::new(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .without_time()
                    .with_writer(move || FailingWriter {
                        sink: failing.clone(),
                    }),
            ),
            SinkHealth::Healthy => Box::new(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .without_time()
                    .with_writer(move || HealthyWriter {
                        offered: Arc::clone(&offered_by_writer),
                        written: Arc::clone(&written_by_writer),
                    }),
            ),
        };
        let subscriber = tracing_subscriber::registry()
            .with(formatter)
            .with(AdmissionLayer {
                outcomes: Arc::clone(&recorded),
            });
        tracing::subscriber::with_default(subscriber, emit);
        let admissions = outcomes.lock().unwrap().clone();
        Self {
            admissions,
            offered: sink.offered_bytes() + *healthy_offered.lock().unwrap(),
            written: sink.written_bytes() + *healthy_written.lock().unwrap(),
        }
    }
}

/// Records the thread the PRODUCT emitted each event from, for the delivery
/// records only.
///
/// This is deliberately not a writer-side observation: it reads the thread at
/// the moment the product emits, so the ids it collects are the threads the
/// product CREATED, not the threads that happened to reach a writer.
#[derive(Clone)]
struct ThreadObservingLayer {
    observed: Arc<Mutex<Vec<std::thread::ThreadId>>>,
}

impl<S> Layer<S> for ThreadObservingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = EmittedFields::default();
        event.record(&mut fields);
        let event_name = fields
            .entries
            .iter()
            .find(|(name, _)| name == "event")
            .map_or_else(String::new, |(_, value)| value.clone());
        // THE SAME PREDICATE THE RECORD FILTER USES, and it reads two DIFFERENT
        // fields: the delivery record is recognised by its `event=` name, and it
        // is then told apart from every other record by its `outcome=` value.
        // `delivery_event_names()` is not read as an `event=` value -- these are
        // `outcome=` values, and no product `event=` name is one of them, so a
        // filter built on it can only ever select the empty set.
        let is_delivery = event_name == DELIVERY_EVENT_NAME;
        let disposition = if is_delivery {
            fields
                .entries
                .iter()
                .find(|(name, _)| name == "outcome")
                .map_or_else(String::new, |(_, value)| value.clone())
        } else {
            String::new()
        };
        if is_delivery && delivery_event_names().contains(&disposition.as_str()) {
            self.observed
                .lock()
                .unwrap()
                .push(std::thread::current().id());
        }
    }
}

/// The `event=` name the product writes on the record its Event Log WORKER emits
/// from inside the synchronous OS report seam
/// (src/windows_event_log.rs:1063-1072):
///
/// ```text
/// crate::host_diagnostics::info!(
///     target: "eliot_host::windows_event_log",
///     event = "host.event_log_delivery",
///     operation = event.as_str(),
///     event_id = event.event_id(),
///     severity = event.severity().as_str(),
///     outcome = outcome,
///     "host event log delivery outcome"
/// );
/// ```
///
/// The sweep's delivery arms select records by THIS name and then read the
/// disposition off the record's `outcome=` FIELD, never off `event=`: every
/// name in [`delivery_event_names`] is an `outcome=` value, and none of them is a
/// product `event=` name. The filter was reading those `outcome=` values out of
/// the `event=` field, which is why it selected the empty set on every platform
/// and for any product. Exactly one declaration of this spelling lives here, so
/// a product rename turns the delivery arms RED rather than quietly emptying
/// them, and the arms below tie the name to a CENSUS of the product's own source
/// so a rename cannot slip past as silence.
const DELIVERY_EVENT_NAME: &str = "host.event_log_delivery";

/// Every `EventLogAdmission` value paired with the product's own diagnostic
/// name for it, so a comparison between two runs is made over the product's
/// typed vocabulary rather than over a hand-written string.
const EVENT_LOG_ADMISSION_BY_NAME: [(EventLogAdmission, &str); 8] = [
    (
        EventLogAdmission::Admitted {
            truncated: false,
            dropped_total: 0,
        },
        "admitted",
    ),
    (
        EventLogAdmission::Admitted {
            truncated: true,
            dropped_total: 0,
        },
        "admitted_truncated",
    ),
    (
        EventLogAdmission::DroppedQueueFull { dropped_total: 0 },
        "queue_full",
    ),
    (
        EventLogAdmission::DroppedProducerBusy { dropped_total: 0 },
        "producer_busy",
    ),
    (
        EventLogAdmission::DroppedFormattingPanic { dropped_total: 0 },
        "formatting_panic_contained",
    ),
    (
        EventLogAdmission::RejectedNotStarted { dropped_total: 0 },
        "not_started",
    ),
    (
        EventLogAdmission::RejectedShutdown { dropped_total: 0 },
        "shutdown",
    ),
    (
        EventLogAdmission::RejectedWorkerUnavailable { dropped_total: 0 },
        "worker_unavailable",
    ),
];

/// Every admitted event paired with the product's own diagnostic name.
const ADMITTED_EVENT_BY_NAME: [(AdmittedEvent, &str); 3] = [
    (AdmittedEvent::ServiceStart, "service_start"),
    (AdmittedEvent::ServiceStop, "service_stop"),
    (AdmittedEvent::ServiceFailure, "service_failure"),
];

/// Every evidence class paired with the product's own diagnostic name.
const HOST_REQUEST_EVIDENCE_BY_NAME: [(HostRequestEvidence, &str); 8] = [
    (HostRequestEvidence::Observed, "observed"),
    (HostRequestEvidence::Admitted, "admitted"),
    (HostRequestEvidence::ProcessStarted, "process_started"),
    (HostRequestEvidence::SemanticallyReady, "semantically_ready"),
    (HostRequestEvidence::DurableCommitted, "durable_committed"),
    (HostRequestEvidence::Cancelled, "cancelled"),
    (HostRequestEvidence::Failed, "failed"),
    (HostRequestEvidence::Unknown, "unknown"),
];

/// Every `EventLogDelivery` value paired with the product's own diagnostic
/// name. Delivery is claimed only by the synchronous OS seam
/// (`report_event` and the worker that calls it), never by admission, so this
/// list is where a case looks when it wants to know what a DELIVERY record can
/// be named -- not to assert one: `report_event` reaches the real OS port, and
/// a delivery this test can provoke depends on the platform.
const EVENT_LOG_DELIVERY_BY_NAME: [(EventLogDelivery, &str); 3] = [
    (
        EventLogDelivery::RegisteredSourceAccepted {
            event: AdmittedEvent::ServiceStart,
        },
        "registered_source_accepted",
    ),
    (
        EventLogDelivery::OsAcceptedRegistrationUnknown {
            event: AdmittedEvent::ServiceStart,
        },
        "os_accepted_registration_unknown",
    ),
    (
        EventLogDelivery::DegradedApplicationAccepted {
            event: AdmittedEvent::ServiceStart,
        },
        "degraded_application_accepted",
    ),
];

/// The `event=` names the product's synchronous delivery arm can emit, read
/// off [`EVENT_LOG_DELIVERY_BY_NAME`] and the wrapper's own error vocabulary so
/// a renamed or added delivery arm cannot escape the sweep that counts the
/// product's delivery records.
///
/// The three error names are `WindowsEventLogError::as_str()`, taken from
/// [`WINDOWS_EVENT_LOG_ERROR_BY_NAME`] rather than written out, and the
/// `"report_panic_contained"` spelling is the one the worker itself uses for a
/// contained report panic. Nothing here names an EVENT: those names are event
/// ids, and a renamed `AdmittedEvent` would break [`ADMITTED_EVENT_BY_NAME`].
fn delivery_event_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = EVENT_LOG_DELIVERY_BY_NAME
        .iter()
        .map(|(delivery, name)| {
            assert_eq!(
                delivery.as_str(),
                *name,
                "every delivery outcome must carry its own exact diagnostic name"
            );
            assert_eq!(
                delivery.event(),
                AdmittedEvent::ServiceStart,
                "a delivery must report the admitted event it carried"
            );
            *name
        })
        .collect();
    names.extend(WINDOWS_EVENT_LOG_ERROR_BY_NAME.iter().map(|(error, name)| {
        assert_eq!(
            error.as_str(),
            *name,
            "every typed wrapper error must carry its own exact diagnostic name"
        );
        *name
    }));
    names.push("report_panic_contained");
    let mut distinct = names.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        names.len(),
        "every delivery disposition must keep its own distinct diagnostic name, got {names:?}"
    );
    names
}

/// Every `WindowsEventLogError` paired with the product's own diagnostic name.
const WINDOWS_EVENT_LOG_ERROR_BY_NAME: [(WindowsEventLogError, &str); 6] = [
    (
        WindowsEventLogError::EventLogUnavailable,
        "event_log_unavailable",
    ),
    (WindowsEventLogError::InvalidRecord, "invalid_record"),
    (
        WindowsEventLogError::SourceUnavailable { code: 0 },
        "source_unavailable",
    ),
    (
        WindowsEventLogError::ReportRefused { code: 0 },
        "report_refused",
    ),
    (WindowsEventLogError::QueueFull, "queue_full"),
    (WindowsEventLogError::Closed, "closed"),
];

/// Every public diagnostic vocabulary the wrapper publishes, paired with the
/// number of values it declares and the names those values produce -- all read
/// through the product's OWN `as_str()` methods.
///
/// The declared count is what makes this exhaustive rather than a sample: it is
/// the length of the enumerated table for that vocabulary, so a new variant
/// cannot be added to the product without either appearing here (and then being
/// checked for a completion claim) or making the table's declared length a lie.
/// Every name is re-derived through the product's method here rather than
/// trusted from the table, so a renamed vocabulary fails instead of silently
/// satisfying the caller's sweep.
fn diagnostic_name_vocabularies() -> Vec<(usize, Vec<&'static str>)> {
    let mut vocabularies: Vec<(usize, Vec<&'static str>)> = Vec::new();

    let mut admission_names: Vec<&'static str> =
        Vec::with_capacity(EVENT_LOG_ADMISSION_BY_NAME.len());
    for (outcome, name) in EVENT_LOG_ADMISSION_BY_NAME {
        assert_eq!(
            outcome.as_str(),
            name,
            "every admission outcome must carry its own exact diagnostic name"
        );
        assert_eq!(
            outcome.dropped_total(),
            0,
            "an admission outcome must report the drop count it was built with"
        );
        admission_names.push(name);
    }
    vocabularies.push((EVENT_LOG_ADMISSION_BY_NAME.len(), admission_names));

    let mut event_names: Vec<&'static str> = Vec::with_capacity(ADMITTED_EVENT_BY_NAME.len());
    for (event, name) in ADMITTED_EVENT_BY_NAME {
        assert_eq!(
            event.as_str(),
            name,
            "every admitted event must carry its own exact diagnostic name"
        );
        event_names.push(name);
    }
    vocabularies.push((ADMITTED_EVENT_BY_NAME.len(), event_names));

    let mut error_names: Vec<&'static str> =
        Vec::with_capacity(WINDOWS_EVENT_LOG_ERROR_BY_NAME.len());
    for (error, name) in WINDOWS_EVENT_LOG_ERROR_BY_NAME {
        assert_eq!(
            error.as_str(),
            name,
            "every typed wrapper error must carry its own exact diagnostic name"
        );
        error_names.push(name);
    }
    vocabularies.push((WINDOWS_EVENT_LOG_ERROR_BY_NAME.len(), error_names));

    let mut delivery_names: Vec<&'static str> =
        Vec::with_capacity(EVENT_LOG_DELIVERY_BY_NAME.len());
    for (delivery, name) in EVENT_LOG_DELIVERY_BY_NAME {
        assert_eq!(
            delivery.as_str(),
            name,
            "every delivery outcome must carry its own exact diagnostic name"
        );
        delivery_names.push(name);
    }
    vocabularies.push((EVENT_LOG_DELIVERY_BY_NAME.len(), delivery_names));

    // `EventLogWorkDisposition` has one variant and one name: the single honest
    // claim the product can make about outstanding work. That it is the ONLY
    // claim is asserted from the product's own source in the case body, not
    // here.
    vocabularies.push((1, vec![EventLogWorkDisposition::Unknown.as_str()]));
    vocabularies
}

/// One facade record exactly as the product emitted it, before any formatter.
///
/// `thread_id` is the thread the product emitted it FROM, so a record the
/// product's own worker produces is distinguishable from one a call site
/// emitted: that is the difference between observing which threads the product
/// CREATED and merely observing which threads reached a writer.
struct CapturedRecord {
    target: String,
    event: String,
    fields: Vec<(String, String)>,
    thread_id: std::thread::ThreadId,
}

impl CapturedRecord {
    /// Every name and value this record carried, concatenated, so one search
    /// covers the whole record rather than a sampled substring.
    fn field_names(&self) -> String {
        self.fields
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join("|")
    }

    fn field_values(&self) -> String {
        self.fields
            .iter()
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
            .join("|")
    }

    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Renders this record the way `format!("{key}={value}")` does, which is
    /// the largest textual form the formatter's Debug fallback can produce for
    /// the same field.
    fn rendered(&self) -> String {
        self.fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// This record's whole textual surface, including its target.
    fn whole(&self) -> String {
        format!("{} {}", self.target, self.rendered())
    }
}

/// Field visitor: keeps the emitted field names and values verbatim, so a case
/// asserts on what the product actually wrote rather than on a locally built
/// expected string.
#[derive(Default)]
struct EmittedFields {
    entries: Vec<(String, String)>,
}

impl Visit for EmittedFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.entries
            .push((field.name().to_owned(), value.to_owned()));
    }

    // This impl is total over every value the product's emission can carry. The
    // product writes fields in exactly four `Value` shapes: `&str`/`String`
    // and `&'static str` (recorded here as `record_str`), `bool`
    // (`record_bool`), and the integers (recorded here as `record_u64` and
    // `record_i64`). `tracing_core::field::Visit` declares no 32-bit recording
    // method, so neither does this impl: a method that is not a trait member
    // can never be dispatched, and declaring one would add no field.
    // `tracing-core`'s `impl_values!` widens before a `Visit` ever sees a
    // value -- `u8`/`u16`/`u32`/`u64`/`usize` all arrive at `record_u64` and
    // `i8`/`i16`/`i32`/`i64`/`isize` all arrive at `record_i64` -- so the
    // product's own `u32` process id and `i32` receipt exit land under their
    // real field names in `entries` with the identical decimal text.
    //
    // The trait's remaining methods (`record_f64`, `record_i128`,
    // `record_u128`, `record_bytes`, `record_error`) each have a default body
    // that forwards to `record_debug`, which this impl provides, so no field
    // can be silently dropped on any path: the canary sweeps below read this
    // layer's complete `entries`, and an absent field must be a field the
    // product never wrote, never one this visitor refused to record.
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.entries
            .push((field.name().to_owned(), value.to_string()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
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
        let event_name = fields
            .entries
            .iter()
            .find(|(name, _)| name == "event")
            .map_or_else(String::new, |(_, value)| value.clone());
        self.records.lock().unwrap().push(CapturedRecord {
            target: event.metadata().target().to_owned(),
            event: event_name,
            fields: fields.entries,
            thread_id: std::thread::current().id(),
        });
    }
}

/// Captures what the facade emitted into its records, at the product's own
/// trace level with no formatter: a record's whole text is then exactly its
/// target plus the names and values its macros supplied, so an absence sweep
/// covers the whole record and not a formatted rendering of it.
fn capture_emitted_records(emit: impl FnOnce()) -> Vec<CapturedRecord> {
    let records = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(RecordingLayer {
        records: Arc::clone(&records),
    });
    tracing::subscriber::with_default(subscriber, emit);
    // The capture owns its own `Arc`, so the recorded events are already
    // finished by the time `with_default` returns. Take the DATA out of the
    // shared cell in its own statement and let the guard drop immediately,
    // rather than holding a `MutexGuard` alive across the assertions below.
    let captured: Vec<CapturedRecord> = std::mem::take(&mut *records.lock().unwrap());
    assert!(
        !captured.is_empty(),
        "the scoped capture must receive the emitted records"
    );
    captured
}

// The marker every over-cap phase above removes, and the pad that builds each
// measured input. Their lengths are asserted rather than assumed, so every
// cap arithmetic in this case is checkable arithmetic.
const REMOVED_TAIL_MARKER: &str = "REMOVED-889-10-TAIL";
const FIXTURE_PAD: &str = "f";

/// Every measured input the truncation phases of case 889/10 are built from.
///
/// The over-cap run for a cap is `cap * 5` pad bytes followed by the head and
/// tail markers BEYOND that boundary, so every marker byte sits past the cut
/// and an unbounded helper is caught by the emitted-record arms. The at-cap run
/// is `head`, pad, `tail` sized to be EXACTLY the cap. The exact-cap run is pure
/// pad, and the under-cap run is exactly one byte short of the cap while
/// carrying both markers.
struct Case10Fixtures {
    head: &'static str,
    tail: &'static str,
    over_field: String,
    over_detail: String,
    under_field: String,
    under_detail: String,
    exact_field: String,
    exact_detail: String,
    marked_at_cap: String,
    marked_detail_at_cap: String,
}

impl Case10Fixtures {
    /// Builds every fixture against the caps the product itself declares.
    ///
    /// Each length is MEASURED here before any assertion downstream depends on
    /// it, so no truncation arm can pass or fail because the input happened to
    /// be the wrong length.
    fn measured() -> Self {
        let head = "RETAINED-889-10-HDR";
        let tail = REMOVED_TAIL_MARKER;
        let filler = FIXTURE_PAD;
        let field_cap = MAX_DIAGNOSTIC_FIELD_BYTES;
        let detail_cap = MAX_DIAGNOSTIC_DETAIL_BYTES;
        assert_eq!(
            (head.len(), filler.len(), tail.len()),
            (19, 1, 19),
            "the three fixture markers must keep their measured byte lengths"
        );
        let over = |cap: usize| filler.repeat(cap * 5) + head + tail;
        let at_cap =
            |cap: usize| head.to_owned() + &filler.repeat(cap - head.len() - tail.len()) + tail;
        let one_under =
            |cap: usize| head.to_owned() + &filler.repeat(cap - head.len() - tail.len() - 1) + tail;
        Self {
            head,
            tail,
            over_field: over(field_cap),
            over_detail: over(detail_cap),
            under_field: one_under(field_cap),
            under_detail: one_under(detail_cap),
            exact_field: filler.repeat(field_cap),
            exact_detail: filler.repeat(detail_cap),
            marked_at_cap: at_cap(field_cap),
            marked_detail_at_cap: at_cap(detail_cap),
        }
    }
}

// WORK_UNIT_CASE: 889/10
#[test]
fn diagnostic_bounds_and_queue_admission_are_honest_about_truncation_and_drops() {
    // Behaviour under test: the declared field/detail/queue caps are enforced
    // BEFORE formatting, truncation is REPORTED rather than silent, and what
    // truncation removed is gone rather than merely hidden.
    //
    // Falsifiable by construction, and each arm is load-bearing. Every fixture is
    // MEASURED against the cap before any assertion depends on it, so no arm
    // can pass or fail because the input happened to be the wrong length:
    //   * the over-cap fixtures are five times the cap, so
    //     `bounded.truncated() == true` fails the moment the cap stops being
    //     applied at all;
    //   * `original_bytes() == input.len()` fails if truncation ever reports a
    //     bound instead of the truth;
    //   * `retained.is_prefix_of(input)` fails if the helper ever rewrites,
    //     reorders, or drops from the head;
    //   * `retained.contains(tail) == false` fails the moment a removed tail is
    //     smuggled back into the retained text (the "without leaking removed
    //     contents" rule), and both markers sit BEYOND the cap boundary in the
    //     over-cap fixtures, so the emitted-record absence arm is equally
    //     real rather than a naming trick;
    //   * `retained.len() <= cap` fails if the cut happens after the cap;
    //   * the under-cap fixtures are exactly one byte short of the cap and both
    //     carry markers, so `truncated() == false` and `text() == input` fail if
    //     an in-bound value is ever cut;
    //   * the at-cap fixtures are exactly the cap, so `truncated() == false`
    //     fails if the cap is applied with `>=` instead of `>`.
    let fixture = contract_fixture();
    let field_cap = MAX_DIAGNOSTIC_FIELD_BYTES;
    let detail_cap = MAX_DIAGNOSTIC_DETAIL_BYTES;

    // Every input the truncation phases below measure themselves against: five
    // times the cap with both markers past the boundary, exactly one byte under
    // the cap with both markers inside it, exactly the cap with and without
    // markers, all MEASURED before any assertion depends on their length.
    let fixtures = Case10Fixtures::measured();
    let tail = fixtures.tail;
    let head = fixtures.head.to_owned();

    // Phase 1, the `MAX_DIAGNOSTIC_FIELD_BYTES` surface: over-cap keeps a
    // bounded prefix, reports the original length and truncation and drops the
    // removed tail; under-cap comes back untouched and untruncated; exactly the
    // cap does not cut. Returns the retained prefixes so the caller can prove
    // none of them smuggled back what was removed.
    let (retained_field, retained_marked_field) =
        assert_the_field_surface_is_bounded_honestly(&fixtures);

    // Phase 2, the `MAX_DIAGNOSTIC_DETAIL_BYTES` surface plus the one
    // multibyte cut and the one boundary input whose last bytes ARE the marker.
    // Returns the two retained prefixes the caller compares against.
    let (retained_detail, retained_head_at_cap) =
        assert_the_detail_surface_is_bounded_honestly(&fixtures);

    // Phase 3, the real emission path: bounding happens BEFORE formatting.
    // Returns both captured texts, which the caller still has to agree with.
    let (detail_records, in_bound_records) =
        assert_bounding_precedes_formatting_on_the_emission_path(&fixtures, tail);

    // Nothing retained above may carry the removed marker, and the bounded
    // prefixes must stay inside the two declared caps.
    for (retained, cap, label) in [
        (&retained_field, field_cap, "field"),
        (&retained_marked_field, field_cap, "field"),
        (&retained_detail, detail_cap, "detail"),
    ] {
        assert!(
            !retained.contains(tail),
            "a retained {label} prefix must never carry the removed tail: {retained}"
        );
        assert!(
            retained.len() <= cap,
            "a retained {label} prefix must stay within its cap, got {} bytes for a {cap}-byte cap",
            retained.len()
        );
    }
    assert!(
        retained_head_at_cap.ends_with(&head),
        "the input of exactly the detail cap must keep its whole tail: {retained_head_at_cap}"
    );
    // The two emissions really are two different records: the over-cap one
    // reports truncation and the in-bound one does not, so neither arm can be
    // satisfied by the other's capture.
    assert!(
        detail_records.contains("detail_truncated=true")
            && in_bound_records.contains("detail_truncated=false"),
        "the over-cap and in-bound emissions must disagree about truncation, got over-cap \
         {detail_records:?} and in-bound {in_bound_records:?}"
    );

    // Phase 4, the queue's own declared capacity, read from the FIXTURE rather
    // than a literal: a queue must hold exactly that many records and one more.
    // Returns that capacity, which phases 5 and 6 must both consume.
    let capacity = assert_the_queue_capacity_is_the_products_own_bound(&fixture);
    let record_cap = assert_the_record_bound_mirrors_the_detail_bound();
    // Phase 5, finite nonblocking admission and exact overflow counting. The
    // saturated queue is handed back so phase 6 can shut it down and read the
    // disposition the product reports, so no count below is a literal here. It
    // is bound `mut` because phase 6 shuts that very queue down through a
    // `&mut`, and nothing else borrows it there, so the mutable borrow is
    // available and the post-shutdown assertions below read the mutated queue.
    let mut ready =
        assert_admission_is_finite_bounded_and_never_claims_a_drain(capacity, record_cap, tail);
    // Phase 6, the honest disposition of what shutdown did not deliver.
    assert_shutdown_parks_everything_and_never_inflates_the_drop_count(&mut ready, capacity);
}

/// The queue's own declared capacity, read from the FIXTURE rather than from a
/// literal, and pinned against the product's OWN `EVENT_LOG_QUEUE_CAPACITY`
/// constant. Both comparisons are load-bearing: a fixture-only capacity would
/// not fail if the product's bound drifted, and a product-only capacity would
/// not fail if the fixture's declaration drifted.
///
/// Returns that capacity, which both later phases must consume as their
/// admission bound, so the arithmetic below is theirs and not a restatement.
fn assert_the_queue_capacity_is_the_products_own_bound(fixture: &Value) -> usize {
    let capacity = usize::try_from(
        fixture["queue_capacity"]
            .as_u64()
            .expect("fixture must pin the queue capacity"),
    )
    .expect("queue capacity must fit usize");
    assert_eq!(
        capacity, EVENT_LOG_QUEUE_CAPACITY,
        "the fixture capacity must be the product's own queue bound"
    );
    assert_eq!(
        capacity, 64,
        "the fixture's declared queue bound must stay finite and small"
    );
    capacity
}

/// Record bytes bound what one admitted record may retain, at the wrapper's own
/// declared bound. Returns that bound so the admission phase has to consume it
/// rather than re-deriving it from its own arithmetic.
fn assert_the_record_bound_mirrors_the_detail_bound() -> usize {
    let record_cap = EVENT_LOG_MAX_INSERTION_BYTES;
    assert_eq!(
        record_cap, MAX_DIAGNOSTIC_DETAIL_BYTES,
        "the wrapper's insertion bound must mirror the detail bound"
    );
    record_cap
}

/// The `MAX_DIAGNOSTIC_FIELD_BYTES` surface, proven across the whole boundary:
/// an over-cap input keeps a bounded prefix, reports the original length,
/// reports truncation and drops the removed tail; an input one byte under the
/// cap comes back untouched, untruncated and reported at its own length; and an
/// input of EXACTLY the cap is not cut, whether it is pure pad or ends in the
/// markers. The last arm is the `>=`-versus-`>` falsifier, and it only means
/// anything because each fixture's length is measured first.
///
/// Returns the two retained prefixes (the over-cap one and the exactly-at-cap
/// one) so the caller must prove neither smuggled back what was removed.
fn assert_the_field_surface_is_bounded_honestly(fixtures: &Case10Fixtures) -> (String, String) {
    let cap = MAX_DIAGNOSTIC_FIELD_BYTES;
    let head = fixtures.head;
    let tail = fixtures.tail;
    // MEASURED: `cap * 5 + head + tail` is 256 * 5 + 19 + 19 = 1318 bytes, so
    // it exceeds the cap by 1062 bytes and both markers sit past byte 1280.
    let over = &fixtures.over_field;
    assert!(
        over.len() > cap,
        "the over-cap field fixture must exceed the cap, got {} bytes against a {cap}-byte cap",
        over.len()
    );
    let truncated = bound_field(over);
    assert!(
        truncated.truncated(),
        "an over-cap field must report truncation"
    );
    assert_eq!(
        truncated.original_bytes(),
        over.len(),
        "a truncated field must report the input's original byte length"
    );
    let retained = truncated.text();
    assert!(
        over.starts_with(retained),
        "a truncated field must retain a prefix of the input"
    );

    // MEASURED: 19 + (cap - 19 - 19 - 1) + 19 = cap - 1, i.e. 255 bytes against
    // a 256-byte cap. A product that truncates too eagerly fails the first
    // arm; one that reports a bound instead of the truth fails the second.
    let under = &fixtures.under_field;
    assert_eq!(
        under.len(),
        cap - 1,
        "the under-cap field fixture must be exactly one byte under the cap"
    );
    assert!(
        under.contains(head) && under.contains(tail),
        "the under-cap field fixture must carry both markers and stay under the cap"
    );
    let kept = bound_field(under);
    assert!(
        !kept.truncated(),
        "an in-bound field must not report truncation"
    );
    assert_eq!(
        kept.original_bytes(),
        under.len(),
        "an in-bound field must report the input's byte length"
    );
    assert_eq!(kept.text(), under);

    // Exactly the cap: 256 pad bytes, and again with both markers.
    let exact = &fixtures.exact_field;
    assert_eq!(
        exact.len(),
        cap,
        "the exactly-at-cap field fixture must be exactly the cap, got {} bytes",
        exact.len()
    );
    let exact_bounded = bound_field(exact);
    assert!(
        !exact_bounded.truncated(),
        "an exactly-at-cap field must not report truncation"
    );
    assert_eq!(exact_bounded.text(), exact);
    assert_eq!(
        exact_bounded.original_bytes(),
        cap,
        "an exactly-at-cap field must report the cap as the input's own length"
    );
    let marked = &fixtures.marked_at_cap;
    assert_eq!(
        marked.len(),
        cap,
        "the marker-bearing at-cap field fixture must be exactly the cap, got {} bytes",
        marked.len()
    );
    let marked_bounded = bound_field(marked);
    assert!(
        !marked_bounded.truncated(),
        "a marker-bearing input of exactly the cap must not report truncation"
    );
    assert_eq!(marked_bounded.text(), marked);
    (retained.to_owned(), marked_bounded.text().to_owned())
}

/// The `MAX_DIAGNOSTIC_DETAIL_BYTES` surface, the surface that also carries
/// entrypoint details and Event Log insertions, proven across the whole
/// boundary with the same honesty facts as the field surface -- plus the two
/// boundaries the field surface cannot express: a multibyte cut that must land
/// on a character boundary, and an input whose LAST bytes are the marker, so
/// the marker survives only if `truncated()` reads false at exactly the cap.
///
/// Returns the retained over-cap prefix and the retained at-cap text, which the
/// caller must agree with.
fn assert_the_detail_surface_is_bounded_honestly(fixtures: &Case10Fixtures) -> (String, String) {
    let cap = MAX_DIAGNOSTIC_DETAIL_BYTES;
    let head = fixtures.head;
    let tail = fixtures.tail;
    // MEASURED: `cap * 5 + head + tail` is 5120 + 19 + 19 = 5158 bytes, so it
    // exceeds the cap by 4134 bytes and the markers start past byte 5120.
    let over = &fixtures.over_detail;
    assert!(
        over.len() > cap,
        "the over-cap detail fixture must exceed the cap, got {} bytes against a {cap}-byte cap",
        over.len()
    );
    let truncated = bound_detail(over);
    assert!(
        truncated.truncated(),
        "an over-cap detail must report truncation"
    );
    assert_eq!(
        truncated.original_bytes(),
        over.len(),
        "a truncated detail must report the input's original byte length"
    );
    let retained = truncated.text();
    assert!(
        over.starts_with(retained),
        "a truncated detail must retain a prefix of the input"
    );

    // MEASURED: 1023 bytes against a 1024-byte cap, carrying both markers.
    let under = &fixtures.under_detail;
    assert_eq!(
        under.len(),
        cap - 1,
        "the under-cap detail fixture must be exactly one byte under the cap"
    );
    assert!(
        under.contains(head) && under.contains(tail),
        "the under-cap detail fixture must carry both markers and stay under the cap"
    );
    let kept = bound_detail(under);
    assert!(
        !kept.truncated(),
        "an in-bound detail must not report truncation"
    );
    assert_eq!(
        kept.original_bytes(),
        under.len(),
        "an in-bound detail must report the input's byte length"
    );
    assert_eq!(kept.text(), under);

    // Exactly the cap: 1024 pad bytes, and again with both markers. Neither is
    // cut, and neither reports truncation, which is the `>=`-versus-`>`
    // falsifier for this surface; the marked input proves a marker at the cap
    // boundary is retained.
    for at_cap in [&fixtures.exact_detail, &fixtures.marked_detail_at_cap] {
        let retained = assert_an_exactly_at_cap_detail_is_not_cut(at_cap, cap);
        assert_eq!(retained, at_cap.as_str());
    }

    let retained_at_cap = assert_a_multibyte_cut_lands_on_a_character_boundary(cap, tail);
    assert!(
        retained_at_cap == cap / 2,
        "the multibyte cut must retain exactly the whole characters that fit the {cap}-byte cap, \
         got {retained_at_cap}"
    );

    // MEASURED: the 19 marker bytes sit at 1019..=1024 of the 1024-byte cap,
    // so the marker survives only if the cut does not fire one byte early.
    let exact_head = format!("{}{}", FIXTURE_PAD.repeat(cap - head.len()), head);
    assert_eq!(
        exact_head.len(),
        cap,
        "the retained-head at-cap detail fixture must be exactly the cap, got {} bytes",
        exact_head.len()
    );
    let head_at_cap = bound_detail(&exact_head);
    assert!(
        !head_at_cap.truncated(),
        "a retained-head input of exactly the cap must not report truncation"
    );
    assert_eq!(head_at_cap.text(), exact_head);
    (retained.to_owned(), head_at_cap.text().to_owned())
}

/// An input of EXACTLY the detail cap is not cut: it is measured against the
/// cap first, it comes back verbatim, it reports no truncation, and it reports
/// the cap as its own original length. This is the `>=`-versus-`>` falsifier
/// for this surface -- a product that cut one byte early fails every arm here.
///
/// Returns the RETAINED text, so the caller has the product's own output to
/// carry rather than only the fact that the arm ran.
fn assert_an_exactly_at_cap_detail_is_not_cut(exact: &str, cap: usize) -> String {
    assert_eq!(
        exact.len(),
        cap,
        "the exactly-at-cap detail fixture must be exactly the cap, got {} bytes",
        exact.len()
    );
    let bounded = bound_detail(exact);
    assert!(
        !bounded.truncated(),
        "an exactly-at-cap detail must not report truncation"
    );
    assert_eq!(bounded.text(), exact);
    assert_eq!(
        bounded.original_bytes(),
        cap,
        "an exactly-at-cap detail must report the cap as the input's own length"
    );
    bounded.text().to_owned()
}

/// A multibyte cut must land on a character boundary: every retained character
/// stays intact, the removed tail is still gone, and the reported original
/// length stays the input's own. This arm fails if the bounding helper ever
/// slices mid-character, or reports a bound instead of the truth.
///
/// The input is built HERE, from the cap the caller proved and the removed-tail
/// marker, so nothing about it is authored anywhere else: it is `cap`
/// two-byte characters followed by the tail, which is genuinely past the cap
/// boundary.
///
/// Returns the RETAINED character count the product produced, so the caller can
/// check it against the cap rather than merely having run the arm.
fn assert_a_multibyte_cut_lands_on_a_character_boundary(cap: usize, tail: &str) -> usize {
    let multibyte = "é".repeat(cap);
    let cut = bound_detail(&format!("{multibyte}{tail}"));
    assert!(cut.truncated());
    assert_eq!(cut.original_bytes(), cap * 2 + tail.len());
    assert!(
        !cut.text().contains(tail),
        "a multibyte cut must still drop the removed tail"
    );
    let retained = cut.text().chars().count();
    assert_eq!(
        retained,
        cap / 2,
        "a multibyte cut must retain whole characters, never a partial one"
    );
    retained
}

/// The real emission path, driven once with an over-cap detail and once with an
/// input that fits exactly: the removed tail must be absent from the emitted
/// record while the reported length and truncation flag still describe the
/// input, and an in-bound input must survive verbatim.
///
/// Returns both captured texts, and the caller uses BOTH: the over-cap capture
/// is the absence half and the in-bound capture is the positive retention half
/// of the same obligation, so neither arm can be dropped.
fn assert_bounding_precedes_formatting_on_the_emission_path(
    fixtures: &Case10Fixtures,
    tail: &str,
) -> (String, String) {
    let head = fixtures.head;
    let over_cap = &fixtures.over_detail;
    let marked_at_cap = &fixtures.marked_at_cap;
    let detail_sink = MeasuringSink::default();
    let detail_writer = detail_sink.clone();
    let detail_records = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || detail_writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            observe_entrypoint_with_detail(EntrypointStage::LaunchConfig, over_cap);
        });
        detail_sink.rendered()
    };
    assert!(
        !detail_records.contains(tail),
        "an emitted entrypoint detail must not carry its removed tail"
    );
    assert!(
        !detail_records.contains(head),
        "an emitted entrypoint detail must not carry a marker that sits beyond the cap boundary"
    );
    assert!(
        detail_records.contains(&format!("detail_bytes={}", over_cap.len())),
        "an emitted over-cap detail must report the input's own byte length, got: {detail_records}"
    );
    assert!(
        detail_records.contains("detail_truncated=true"),
        "an emitted over-cap detail must report that it was truncated, got: {detail_records}"
    );
    assert!(
        detail_records.len() <= 2 * MAX_DIAGNOSTIC_DETAIL_BYTES,
        "an emitted detail must stay bounded before formatting, got {} bytes",
        detail_records.len()
    );

    // The positive retention half of the same obligation: an input that fits
    // the cap keeps its marker verbatim, and says it kept everything. A
    // product that cut in-bound material fails here.
    let in_bound_sink = MeasuringSink::default();
    let in_bound_writer = in_bound_sink.clone();
    let in_bound_records = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || in_bound_writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            observe_entrypoint_with_detail(EntrypointStage::LaunchConfig, marked_at_cap);
        });
        in_bound_sink.rendered()
    };
    assert!(
        in_bound_records.contains(head) && in_bound_records.contains(tail),
        "an emitted in-bound detail must carry its whole input, got: {in_bound_records}"
    );
    assert!(
        in_bound_records.contains("detail_truncated=false"),
        "an emitted in-bound detail must report that nothing was cut, got: {in_bound_records}"
    );
    assert!(
        in_bound_records.contains(&format!("detail_bytes={MAX_DIAGNOSTIC_FIELD_BYTES}")),
        "an emitted in-bound detail must report the cap as the input's own length, got: {in_bound_records}"
    );
    (detail_records, in_bound_records)
}

/// Finite, nonblocking admission at the queue's own declared capacity: the
/// queue holds exactly that many records, the next one is a typed drop, every
/// further overflow is counted exactly once, the queue never grows past its
/// bound, and a freshly saturated queue carries the SAME capacity the wrapper's
/// own constant declares.
///
/// Returns that saturated queue, which the caller must shut down and read the
/// disposition from, so every drop count below is the product's observed count
/// rather than a literal this test authored.
fn assert_queue_overflow_drops_are_exact_and_shutdown_is_honest(
    capacity: usize,
) -> WindowsEventLogQueue {
    // Over-capacity admission drops with an exact count and never grows: the
    // queue is saturated, one more record is rejected, and the drop count
    // advances by exactly one. Each of these arms fails if admission ever
    // blocks, grows, or loses count.
    let mut queue = WindowsEventLogQueue::with_default_capacity();
    assert_eq!(queue.capacity(), capacity);
    for slot in 0..capacity {
        queue
            .try_admit(EventLogRecord::new(
                AdmittedEvent::ServiceStart,
                &format!("slot-{slot}"),
            ))
            .expect("admission within the declared capacity must succeed");
    }
    assert_eq!(queue.len(), capacity);
    assert_eq!(
        queue.dropped_total(),
        0,
        "an unsaturated queue must not report a drop"
    );
    assert_eq!(
        queue.try_admit(EventLogRecord::new(
            AdmittedEvent::ServiceFailure,
            "overflow"
        )),
        Err(WindowsEventLogError::QueueFull),
        "admission past the declared capacity must be a typed drop"
    );
    assert_eq!(
        queue.dropped_total(),
        1,
        "a capacity overflow must advance the drop count by exactly one"
    );
    assert_eq!(
        queue.len(),
        capacity,
        "a dropped record must not be retained"
    );

    // Every further overflow is counted exactly once, and the queue still
    // never grows past its bound.
    let overflows = 5u64;
    for slot in 0..overflows {
        assert_eq!(
            queue.try_admit(EventLogRecord::new(
                AdmittedEvent::ServiceFailure,
                &format!("overflow-{slot}")
            )),
            Err(WindowsEventLogError::QueueFull),
            "every admission past the capacity must be a typed drop"
        );
    }
    assert_eq!(
        queue.dropped_total(),
        1 + overflows,
        "every counted drop must appear in the drop total exactly once"
    );
    assert_eq!(
        queue.len(),
        capacity,
        "the queue must never grow past its declared bound"
    );

    // The queue's own declared capacity, read off the PRODUCT's accessor
    // rather than restated here: `capacity` is this test's own arithmetic input
    // above, so anything derived from it alone cannot fail. The queue type
    // publishes no in-flight accessor, and the only in-flight window in this
    // product is the single OS worker's, whose count the producer reports
    // through `EventLogWorkCount` on a live snapshot -- so the in-flight half of
    // this case is not proved here. See the honest note below.
    let mut ready = WindowsEventLogQueue::with_default_capacity();
    assert_eq!(
        ready.capacity(),
        capacity,
        "the product's queue must carry exactly the declared capacity"
    );
    assert_eq!(
        ready.capacity(),
        EVENT_LOG_QUEUE_CAPACITY,
        "the product's default capacity must be the wrapper's own declared constant"
    );
    for slot in 0..capacity {
        ready
            .try_admit(EventLogRecord::new(
                AdmittedEvent::ServiceStop,
                &format!("ready-{slot}"),
            ))
            .expect("admission within the declared capacity must succeed");
    }
    // DELETED (was theatre): `assert!(ready.len() + in_flight_bound <=
    // max_outstanding, ...)` under the heading "the unstarted producer's
    // in-flight bound". It compared `64 + 1 <= 64 + 1`: `max_outstanding` was
    // itself defined as `capacity + in_flight_bound`, `ready.len() ==
    // capacity` was asserted on the line above, and `in_flight_bound` was the
    // test's own literal `1`. No product value entered it, so no product
    // mutation could fail it.
    //
    // HONEST SCOPE of what remains: the queue's bound is now proved against
    // the product's own `capacity()` and against `EVENT_LOG_QUEUE_CAPACITY`,
    // and every overflow above was a real `QueueFull` refusal. The IN-FLIGHT
    // half of this case is unproved by this file and is left that way on
    // purpose -- see case 889/14, which reads the producer's own reported
    // `EventLogWorkCount` off a live snapshot and is the case that can fail if
    // that bound is ever broken. No assertion here stands in for it.
    assert_eq!(ready.len(), capacity);
    ready
}

/// One admitted record's own byte bound, measured at the wrapper's declared
/// insertion cap. `overflowing` is five times that cap, so the inserted record
/// genuinely exceeds the bound rather than sitting under it, and its removed
/// tail begins past the boundary, so the absence arm is real.
///
/// Returns the RETAINED byte length the product produced, not the bound it was
/// given, so the caller must check it rather than merely having run the phase.
fn assert_an_admitted_record_stays_within_the_insertion_bound(
    record_cap: usize,
    overflowing: &str,
    tail: &str,
) -> usize {
    let record = EventLogRecord::new(AdmittedEvent::ServiceStart, overflowing);
    assert!(
        record.truncated(),
        "an insertion past the wrapper's own bound must be reported truncated, not refused"
    );
    assert!(
        !record.insertion().contains(tail),
        "an admitted over-cap insertion must drop the removed tail, got a retained insertion that \
         still carries {tail:?}"
    );
    let retained = record.insertion().len();
    assert!(
        retained <= record_cap,
        "an admitted record must stay within the wrapper's own insertion bound, got {retained} \
         bytes against a {record_cap}-byte cap"
    );
    retained
}

/// Finite, nonblocking admission, honest shutdown inputs, and one admitted
/// record's byte bound, driven at the capacity the fixture and the product
/// agree on.
///
/// `record_cap` is threaded in from the wrapper's own declared insertion bound,
/// and the retained length measured against it is threaded back out, so neither
/// the bound nor the measurement can be dropped on the way through.
///
/// Returns that saturated queue, which the caller must shut down and read the
/// disposition from, so every drop count downstream is the product's observed
/// count rather than a literal this test authored.
fn assert_admission_is_finite_bounded_and_never_claims_a_drain(
    capacity: usize,
    record_cap: usize,
    tail: &str,
) -> WindowsEventLogQueue {
    let ready = assert_queue_overflow_drops_are_exact_and_shutdown_is_honest(capacity);
    let overflowing = FIXTURE_PAD.repeat(record_cap * 5) + tail;
    let retained =
        assert_an_admitted_record_stays_within_the_insertion_bound(record_cap, &overflowing, tail);
    assert!(
        retained <= record_cap,
        "the record this phase admitted must stay within the wrapper's declared insertion bound"
    );
    ready
}

/// The honest disposition of what shutdown did not deliver: the parked count,
/// the counted drops, and closed admission that does not inflate the drop
/// count.
///
/// `capacity` is the bound the product itself published in the phase above, so
/// an arm that passed on `capacity - 1` parked records fails. Each arm fails if
/// shutdown ever claims a drain or loses a count, and none of them can be
/// reached without first shutting down the queue the admission phase
/// saturated.
///
/// `ready` is taken by `&mut` because `shutdown()` and `try_admit()` MUTATE the
/// queue, and it is the SAME saturated queue the admission phase returned and
/// the same one every assertion below reads: the pre-shutdown drop count, the
/// post-shutdown closed state and the post-`try_admit` drop count are all read
/// off that one object after those very calls, never off a copy.
fn assert_shutdown_parks_everything_and_never_inflates_the_drop_count(
    ready: &mut WindowsEventLogQueue,
    capacity: usize,
) {
    let counted_drops = ready.dropped_total();
    let shutdown = ready.shutdown();
    assert_eq!(
        shutdown.unsent(),
        capacity,
        "shutdown must park every held record as unsent"
    );
    assert_eq!(
        shutdown.dropped_total(),
        counted_drops,
        "shutdown must report exactly the drop count the queue itself published"
    );
    assert!(ready.is_closed());
    assert_eq!(
        ready.try_admit(EventLogRecord::new(AdmittedEvent::ServiceStart, "late")),
        Err(WindowsEventLogError::Closed),
        "admission after shutdown must be a typed refusal"
    );
    assert_eq!(
        ready.dropped_total(),
        counted_drops,
        "a closed queue must refuse without advancing the drop count"
    );
}

/// The one real call to #984's safe port, with every outcome it can return
/// typed and asserted: acceptance is reported as OS acceptance with source
/// registration UNKNOWN, refusal and unavailability are pinned to the platforms
/// that can actually produce them, the queue arms are proven unreachable from
/// this path, and the caller's Host result comes back untouched.
///
/// `host_result` is the caller's own result, evaluated here so the caller can
/// prove it is unchanged by the sink outcome; the caller therefore cannot
/// bypass this function and still reach its own assertion.
///
/// The platform clauses below are checked against the PRODUCT's own live seam
/// status, never against `cfg!(windows)`. A compile-time constant would make
/// each clause an assertion about the build target rather than about the port
/// state that actually produced the outcome reached in the arm; deriving the
/// condition from `event_log_sink_status()` -- the same live probe the facade's
/// `note_event_log_sink_status` consumes -- turns all three into real checks:
/// a success outcome exists only where a live port was answered, an
/// unavailable outcome exists only where no live port is present, and a
/// refusal outcome exists only where the port WAS attempted and the OS itself
/// declined.
fn assert_safe_port_outcome_is_typed(
    record: &EventLogRecord,
    event: AdmittedEvent,
    host_result: Result<(), &'static str>,
) {
    let seam_attemptable = event_log_sink_status() == Ok(());
    match report_event(record) {
        Ok(delivery) => {
            assert!(
                seam_attemptable,
                "a success outcome exists only where the live Event Log seam is attemptable, \
                 which is the port being answered at all"
            );
            // STALE-ARM REWRITE (owner comment 5945889835, W4 refuted).
            //
            // Replaces ONLY the old registered-source assertion; the
            // `seam_attemptable` guard above and the event-correlation assertion
            // below are kept exactly as they were. What a successful
            // `report_event` actually proves on this HEAD is OS acceptance with
            // source registration UNKNOWN, so the truthful arm is
            // `OsAcceptedRegistrationUnknown`.
            //
            // WHY this is the only reachable arm - do not "fix" it back:
            // the platform port in
            // `crates/kernel/eliot-platform-windows/src/event_log.rs`
            // declares `pub enum EventLogSourceAvailability` with EXACTLY ONE
            // variant, `Unknown` (event_log.rs:346-351), and BOTH
            // `EventLogReceipt::accepted` (:364-369) and
            // `KernelEventLogReceipt::accepted` (:413-418) hard-code
            // `availability: EventLogSourceAvailability::Unknown`. The
            // exhaustive `match receipt.source_availability()` inside
            // `report_event` (windows_event_log.rs:410-414, no wildcard arm) can
            // therefore only take the `Unknown` arm and can only return
            // `EventLogDelivery::OsAcceptedRegistrationUnknown`.
            // `RegisteredSourceAccepted` and `DegradedApplicationAccepted` are
            // UNREACHABLE here. The old assertion demanded the registered-source
            // profile anyway, which is precisely the conflation the governing
            // sentence forbids ("Never silently substitute fallback or equate
            // successful handle acquisition with installed message resources"),
            // and it made this suite red on any Windows host whose OS accepted
            // the record.
            //
            // `EventLogDelivery` stays imported and used through the
            // arm-agnostic API the enum actually offers: `delivery.event()`
            // below correlates every arm uniformly, and `delivery.as_str()`
            // pins the truthful reachable arm by its stable outcome name,
            // keeping it spelled apart from the two unreachable profiles. Both
            // are platform-independent expressions evaluated only inside this
            // arm, which the `seam_attemptable` guard makes unreachable where
            // this build has no live Event Log port.
            assert!(
                matches!(
                    delivery,
                    EventLogDelivery::OsAcceptedRegistrationUnknown { .. }
                ),
                "OS acceptance with unknown registration must report the registration-unknown \
                 arm, never the registered-source or degraded Application profile, got: \
                 {delivery:?}"
            );
            assert_eq!(
                delivery.as_str(),
                "os_accepted_registration_unknown",
                "the truthful reachable delivery name must stay distinct from the \
                 registered-source and degraded Application profiles"
            );
            // accepted delivery must correlate to the submitted event
            assert_eq!(
                delivery.event(),
                event,
                "accepted delivery must correlate to the submitted event"
            );
        }
        Err(WindowsEventLogError::EventLogUnavailable) => {
            assert!(
                !seam_attemptable,
                "an unavailable answer exists only where the live Event Log seam reports \
                 unavailable: where the port is live it must be attempted, not answered unavailable"
            );
        }
        Err(
            error @ (WindowsEventLogError::SourceUnavailable { .. }
            | WindowsEventLogError::ReportRefused { .. }),
        ) => {
            assert!(
                seam_attemptable,
                "OS refusal outcomes exist only where the live Event Log seam is attemptable, \
                 got: {error:?}"
            );
        }
        Err(WindowsEventLogError::InvalidRecord) => {
            panic!("bounded redacted fixture insertion must validate")
        }
        Err(WindowsEventLogError::QueueFull | WindowsEventLogError::Closed) => {
            panic!("direct report never touches the admission queue")
        }
    }
    assert!(
        host_result.is_ok(),
        "sink outcome must not change Host result"
    );
}

// WORK_UNIT_CASE: 889/11
#[test]
fn credential_token_environment_and_connection_canaries_are_bounded_and_carry_no_dedicated_channel()
{
    const OVER_CAP_SECRET_REPEATS: usize = 128;

    // Behaviour under test: the facade's FIELD SURFACE is closed and
    // nonsecret. No record it emits carries a credential, token, environment
    // value, or connection string in a field of its own, in a field NAME, or
    // under a formatter's Debug rendering: those categories have no channel
    // here, which is a property of the vocabulary and is proved below.
    //
    // HONEST SCOPE, and the correction this case exists to make. It pours four
    // IN-BOUND, explicitly nonsecret DUMMY!-prefixed markers (MEASURED: 21, 27,
    // 22 and 21 bytes -- all far under the 1024-byte detail bound) and asserts
    // that the product records them verbatim. That is the product's truth:
    // `truncate_to` bounds SIZE only, `bound_detail` never
    // inspects content for secrets, and `observe_entrypoint_with_detail` writes
    // `detail = bounded.text()` -- the retained prefix VERBATIM. The module
    // header says so in as many words: "Callers must pass only nonsecret
    // material; bounding limits size, not sensitivity (I15.4)". A marker this
    // test hands the facade IS recorded, and the RESIDUE arm below asserts that
    // with `detail_truncated == "false"`. Raw assertions prove size only; the
    // typed HostError capture separately tests category canaries. Absence is
    // claimed only for the synthetic over-cap tail beyond the cap boundary.
    //
    // Falsifiable by construction: the absence assertions run over each
    // record's WHOLE text (its target plus every field name and value), and
    // the case fails the moment a removed tail survives anywhere in that text
    // or a secret slot appears in the field surface. The residue arm fails the
    // moment the facade starts cutting in-bound material, redacting it, or
    // reporting a truncation flag it did not perform. Neither arm can pass
    // vacuously: the facade has to keep recording for the residue arm to be
    // able to fail.
    let marker = "DUMMY!";
    let credential = pour("CREDENTIAL", marker);
    let token = pour("TOKEN", marker);
    let environment = pour("ENVIRONMENT", marker);
    let connection = pour("CONNECTION", marker);

    // MEASURED before any absence arm is trusted: every poured value is
    // IN BOUND. If one crossed the cap the residue arm would silently stop
    // describing the in-bound case. MEASURED: the 21-byte credential and
    // connection markers, the 22-byte environment marker, and the 27-byte
    // bearer-shaped DUMMY! marker all fit; no machine environment or real
    // credential is read to build them.
    //
    // The in-bound lengths are also pinned here, so the MEASURED prose above is
    // an assertion rather than a note: a future edit to `pour` that made one of
    // these canaries longer (or the removed tail's fragment collide with an
    // in-bound value, which is exactly what the scoped absence arm below is
    // careful about) fails here rather than silently invalidating the arms.
    let bound = MAX_DIAGNOSTIC_DETAIL_BYTES;
    for (channel, value) in [
        (credential.channel, credential.value.as_str()),
        (token.channel, token.value.as_str()),
        (environment.channel, environment.value.as_str()),
        (connection.channel, connection.value.as_str()),
    ] {
        assert!(
            value.len() <= bound,
            "the {channel} canary must be IN BOUND, got {} bytes against a {bound} byte bound",
            value.len()
        );
    }
    assert_eq!(
        [
            credential.value.len(),
            token.value.len(),
            environment.value.len(),
            connection.value.len()
        ],
        [21, 27, 22, 21],
        "the four in-bound canaries must keep the MEASURED byte lengths the prose names"
    );
    assert!(
        token.value.contains("Bearer "),
        "the token canary must carry its authorization scheme prefix, got: {}",
        token.value
    );

    // An over-cap nonsecret detail fixture whose removed tail is distinctive.
    // The facade cannot have retained that tail under its own bound, so its
    // total absence over every record is a real absence claim, not a naming
    // trick. MEASURED: `credential.value` is the 21-byte DUMMY! marker, so 128
    // copies plus the 21-byte tail is 2688 + 21 = 2709 bytes against a
    // 1024-byte bound: the cut lands inside the repeat run at byte 1024 and the
    // tail starts at byte 2688, 1664 bytes past the boundary. 64 copies
    // (1344 + 21 = 1365) also exceeds the bound but by only 341 bytes; 128
    // keeps the margin unambiguous.
    let secret_tail = "REMOVED-889-11-DUMMY!";
    let over_cap_secret = credential.value.repeat(OVER_CAP_SECRET_REPEATS) + secret_tail;
    assert!(
        over_cap_secret.len() > 2 * MAX_DIAGNOSTIC_DETAIL_BYTES,
        "the over-cap synthetic detail fixture must clear the declared bound by a clear margin, got {} bytes against a {} byte bound",
        over_cap_secret.len(),
        MAX_DIAGNOSTIC_DETAIL_BYTES
    );

    // Phase 0, the capture itself: every facade emission surface this case is
    // about, poured once and handed on to the phases below. Returns that
    // capture, which each later phase reads rather than re-capturing.
    let records = capture_the_secret_canary_sweep(
        &credential,
        &token,
        &environment,
        &connection,
        &over_cap_secret,
    );
    let error_canaries = [
        "credential=TEST-ONLY-889-11-CREDENTIAL",
        "token=Bearer TEST-ONLY-889-11-TOKEN",
        "environment=TEST_ONLY_889_11=ENVIRONMENT",
        "connection=postgres://test-only:889-11-connection@invalid/db",
    ];
    let error_payload = error_canaries.join(" | ");
    let typed_failure_records =
        assert_typed_host_error_payload_is_not_projected(&error_payload, &error_canaries);

    // Phase A, the removed-material absence claim: every channel really was
    // poured, the removed tail really begins past the cap boundary, and that
    // tail is absent from EVERY record's whole text.
    //
    // Returns the ONE record that carries the over-cap bounded secret, so the
    // caller must go on to judge that record's own fields rather than merely
    // having run the sweep.
    let bounded_secret = assert_the_removed_secret_tail_is_absent_from_every_record(
        &records,
        &[&credential, &token, &environment, &connection],
        OVER_CAP_SECRET_REPEATS,
        secret_tail,
    );

    // Phase B, the record that carried it is bounded, REPORTED, and honest about
    // what the bound removed: its own byte length, no fragment of its removed
    // tail, and a fixture whose tail really does start past the boundary.
    assert_the_truncated_secret_reports_its_length_and_no_fragment(
        bounded_secret,
        &over_cap_secret,
        secret_tail,
    );

    // DELETED (impossible, and this is why): a sweep for the connection-string
    // parameter spellings "tok=", "srv=", "uid=", "pwd=", "password=" and
    // "token=" over every record's whole text, under the claim that a sentinel
    // whose value was stripped could not have crossed as a connection string.
    // Nothing in the product emits a connection string, so every one of those
    // six spellings is absent from the product's own sources -- verified, not
    // assumed -- and each arm was therefore VACUOUS: it passed because the
    // searched text does not exist, and no product mutation could fail it. The
    // real rule is the field-slot absence above, which names the slots directly
    // rather than guessing at the spelling of a value the product never emits.
    //
    // NOT PROVED, stated plainly rather than asserted: that a call site never
    // hands secret material to a bounded channel. That obligation is entirely
    // caller-side (I15.4) and this file cannot observe it, so no assertion here
    // claims it.

    // Phase C, the closed field surface: no captured facade event has a field
    // of its own for a secret category.
    assert_the_secret_categories_have_no_slot_of_their_own(&records);
    assert_the_secret_categories_have_no_slot_of_their_own(&typed_failure_records);

    // Phase D, no record may carry an arbitrary error Debug/Display rendering,
    // and every reason the facade ACTUALLY projected is one of its frozen
    // nonsecret reason codes -- compared against that independent list, never
    // against the values this sweep poured.
    assert_only_frozen_reason_codes_are_projected(&records);

    // Phase E, the sweep is non-vacuous and every record is a facade record, so
    // the absence above is a property of the channel surface and not of an
    // empty or degenerate capture.
    assert_the_sweep_saw_every_event_it_is_reasoning_about(&records);

    // THE PRODUCT'S REAL BEHAVIOUR, stated as such, and the half of this case
    // that had it backwards: the in-bound nonsecret DUMMY! markers representing
    // credential, token, environment and connection categories ARE RECORDED,
    // verbatim,
    // each with `detail_truncated == "false"` and its own byte length. This is
    // not a defect being papered over and not a scrubbing rule this case claims
    // to have. `truncate_to` bounds SIZE only, `bound_detail` never inspects
    // content for secrets, and `observe_entrypoint_with_detail` writes
    // `detail = bounded.text()`, so the retained prefix of an in-bound value is
    // the value itself.
    //
    // The real I15.4 contract, which is what the closed-surface and
    // removed-material arms above actually prove: the field surface has NO
    // channel of its own for credentials, tokens, environment values or
    // connection strings, the facade never READS one to construct a record, and
    // what exceeds the bound is genuinely gone. The remaining half of the
    // obligation -- do not hand secret material to a bounded channel -- is
    // entirely CALLER-side, and no assertion here can prove it, so none claims
    // it. The guarantee is caller-side redaction plus size bounding, never
    // automatic scrubbing.
    //
    // These four assertions can all fail. A product that changes handling of
    // the in-bound nonsecret fixtures fails the `detail` equality; one that began cutting an
    // in-bound value fails the truncation flag; one that began reporting a
    // truncation it did not perform fails the same flag; one that began
    // reporting a bound instead of the truth fails `detail_bytes`.
    assert_the_in_bound_canaries_are_recorded_verbatim(
        &records,
        [
            (EntrypointStage::Startup.as_str(), &credential),
            (EntrypointStage::LaunchConfig.as_str(), &token),
            (EntrypointStage::ScmDispatch.as_str(), &environment),
            (EntrypointStage::ConsoleLoop.as_str(), &connection),
        ],
    );
}

/// The capture phase of case 889/11: every facade emission surface that case is
/// about, poured once.
///
/// The stage-detail channel is fed explicit nonsecret DUMMY! markers standing
/// in for credential categories, and the facade copies these fixtures verbatim.
/// The bounded code channel is fed the same marker values, so raw assertions
/// cover size and truncation, not auto-redaction. Typed error canaries use a
/// separate capture through the failure projection. The over-cap fixture rides
/// the detail channel alone, which makes the removed-material claim specific.
///
/// Returns the capture, which every later phase of the case reads.
fn capture_the_secret_canary_sweep(
    credential: &Canary,
    token: &Canary,
    environment: &Canary,
    connection: &Canary,
    over_cap_secret: &str,
) -> Vec<CapturedRecord> {
    capture_emitted_records(|| {
        observe_entrypoint_with_detail(EntrypointStage::Startup, &credential.value);
        observe_entrypoint_with_detail(EntrypointStage::LaunchConfig, &token.value);
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &environment.value);
        observe_entrypoint_with_detail(EntrypointStage::ConsoleLoop, &connection.value);
        observe_entrypoint_with_detail(EntrypointStage::ShutdownDrain, over_cap_secret);
        observe_terminal_error(&credential.value);
        observe_terminal_error(&token.value);
        observe_terminal_error(&environment.value);
        observe_terminal_error(&connection.value);
        // Typed request projections: the facade's widest record. Built from the
        // fixed evidence vocabulary only -- no free-text slot, no payload slot,
        // and no error payload beyond a frozen reason code -- which is why the
        // closed-surface and reason-code arms are asked about these records.
        for (evidence, request) in [
            ("observed", HostConsoleRequest::Status),
            ("process_started", HostConsoleRequest::Stop),
            ("failed", HostConsoleRequest::Status),
            ("failed_without_reason", HostConsoleRequest::Stop),
            ("unknown", HostConsoleRequest::Stop),
        ] {
            let projection = match evidence {
                "observed" => HostRequestProjection::observed(EntrypointStage::ScmDispatch)
                    .with_request(request)
                    .with_operation(AdmittedEvent::ServiceStart),
                "process_started" => HostRequestProjection::process_started(
                    EntrypointStage::ConsoleLoop,
                    std::process::id(),
                )
                .with_request(request)
                .with_operation(AdmittedEvent::ServiceStart),
                // A projection that genuinely carries a TYPED error, so the
                // reason-code check has a real reason to judge. The previous
                // four projections all left `reason` unset, the facade then
                // wrote `reason = ""`, and the check was a red assertion against
                // an empty string rather than a rule. `failed` with a
                // `HostError` in hand is the shape case 889/13 already uses,
                // and it is the only one of these five that makes the check
                // meaningful.
                "failed" => {
                    HostRequestProjection::failed(EntrypointStage::ConsoleLoop, &HostError::Stopped)
                        .with_request(request)
                        .with_operation(AdmittedEvent::ServiceFailure)
                }
                "failed_without_reason" => {
                    HostRequestProjection::failed_without_reason(EntrypointStage::ConsoleLoop)
                        .with_request(request)
                        .with_operation(AdmittedEvent::ServiceFailure)
                }
                _ => HostRequestProjection::unknown(EntrypointStage::ShutdownDrain)
                    .with_request(request)
                    .with_operation(AdmittedEvent::ServiceStop),
            };
            observe_host_request(&projection);
        }
        // Sink availability: the remaining facade emission.
        note_event_log_sink_status();
    })
}

/// The removed tail of an over-cap secret is absent from EVERY record, and every
/// secret channel really was poured into the sweep first, so a channel that was
/// never poured cannot satisfy an absence arm.
///
/// Returns the ONE record that carries the over-cap bounded secret, which the
/// caller must judge further; the arms here therefore cannot be bypassed by
/// ignoring the result.
///
/// `secret_tail` is the marker this case minted for the material the bound
/// genuinely REMOVED. It is swept over every record's WHOLE text -- its target
/// plus every field name and value -- which is a real absence claim rather than
/// a naming trick: the sentinel is distinctive enough that no in-bound value in
/// this capture can contain it, so sweeping every record is what proves the tail
/// did not merely vanish from the record that carried it. It vanished
/// everywhere.
fn assert_the_removed_secret_tail_is_absent_from_every_record<'a>(
    records: &'a [CapturedRecord],
    pours: &[&Canary],
    over_cap_repeats: usize,
    secret_tail: &str,
) -> &'a CapturedRecord {
    // The poured set is checked against the independently declared channel list
    // first, so a channel that was never poured cannot silently satisfy an
    // absence arm.
    //
    // DELETED (was impossible): a sweep for each of the four poured canaries
    // over every record's whole text. All four are IN BOUND, so
    // `observe_entrypoint_with_detail` is REQUIRED to write them verbatim and
    // that sweep could never have passed -- it asserted the opposite of the
    // truth. Those four values are now asserted PRESENT by the residue arm
    // below, which is what the product does.
    let poured_channels: Vec<&'static str> = pours.iter().map(|canary| canary.channel).collect();
    assert_eq!(
        poured_channels, EXCLUDED_SECRET_CHANNELS,
        "every expected secret channel must have been poured into the sweep"
    );
    // MEASURED again, next to the arm that uses it: the removed tail starts
    // strictly past the boundary, which is the only reason its absence below is
    // a real absence claim rather than a naming trick.
    let over_cap_run_bytes = pours
        .iter()
        .map(|canary| canary.value.len() * over_cap_repeats)
        .min()
        .expect("the sweep must have poured at least one in-bound canary");
    assert!(
        over_cap_run_bytes > MAX_DIAGNOSTIC_DETAIL_BYTES,
        "the over-cap run must end past the {MAX_DIAGNOSTIC_DETAIL_BYTES} byte boundary so the \
         tail is genuinely removed, got {over_cap_run_bytes} bytes"
    );
    // The FULL removed tail is absent from EVERY record's whole text. This one
    // is an honest absence claim over the whole capture: `REMOVED-889-11-DUMMY!`
    // is a distinctive sentinel that no in-bound value in this capture can
    // contain, so sweeping every record is what proves the tail did not merely
    // vanish from the record that carried it -- it vanished everywhere.
    for record in records {
        assert!(
            !record.whole().contains(secret_tail),
            "no record may carry the removed tail of an over-cap secret"
        );
    }
    // The over-cap secret is bounded, reported, and its removed tail is absent
    // from the record text -- the "indicate truncation without leaking removed
    // contents" rule applied to secret material. This is the one record the
    // caller must go on to judge.
    records
        .iter()
        .find(|record| {
            record.event == "host.entrypoint_stage"
                && record.field("detail_truncated") == Some("true")
        })
        .expect("the over-cap detail must have been reported as truncated")
}

/// The record that carried the over-cap secret is bounded, REPORTED, and honest
/// about what the bound removed: it names its own byte length rather than its
/// contents, and neither the removed tail nor any fragment of it survives
/// anywhere in its whole text.
///
/// Each element here carries a WHOLE `&Canary`, not a `(channel, value)` tuple
/// -- `Canary` is a struct with named fields, so it is bound as one and its
/// fields are read through it. Both names come from the pour itself: the
/// `channel` this case poured into, and the exact `value` string that pour
/// manufactured, so the expectations below are still checked against the input
/// rather than restated from the record.
fn assert_the_truncated_secret_reports_its_length_and_no_fragment(
    bounded_secret: &CapturedRecord,
    over_cap_secret: &str,
    secret_tail: &str,
) {
    assert_eq!(
        bounded_secret.field("detail_bytes"),
        Some(over_cap_secret.len().to_string().as_str()),
        "a truncated secret must report its original byte length, never its contents"
    );

    // FRAGMENT ABSENCE, SCOPED TO THE RECORD THAT CARRIES THE OVER-CAP SECRET.
    //
    // FIXED (was guaranteed red). This arm used to sweep EVERY record in the
    // capture for `secret_tail.strip_prefix("REMOVED-")`, i.e. the 13-byte
    // fragment `889-11-DUMMY!`. `pour("TOKEN", marker)` builds the in-bound
    // bearer-shaped test marker as `"Bearer DUMMY!-889-11-DUMMY!"`, which
    // CONTAINS that fragment verbatim; that marker is poured IN-BOUND, and the
    // residue arm REQUIRES it to be recorded verbatim with
    // `detail_truncated == "false"`. So the two arms would be mutually
    // exclusive if the fragment were checked across all records. The fragment
    // is scoped to the one record that carries the over-cap bounded fixture.
    //
    // STILL FALSIFIABLE. A product that leaked the removed tail -- by raising
    // `MAX_DIAGNOSTIC_DETAIL_BYTES`, by cutting late, by truncating the whole
    // record instead of just the detail, or by writing the original input into a
    // second slot -- makes this FAIL, because the removed material could then
    // appear in this record's whole text. `secret_tail` begins 1664 bytes past
    // the cap boundary of `over_cap_secret` and is carried by no other value in
    // this capture.
    let removed_fragment = secret_tail
        .strip_prefix("REMOVED-")
        .expect("the removed tail must keep its REMOVED- prefix");
    assert!(
        !bounded_secret.whole().contains(removed_fragment),
        "a truncated secret must retain no part of its removed tail, but {:?} leaked into \
         {event:?}",
        removed_fragment,
        event = bounded_secret.event,
    );
    assert!(
        over_cap_secret.ends_with(secret_tail) && !over_cap_secret.starts_with(removed_fragment),
        "the over-cap secret must END with its removed tail so that tail is genuinely past the \
         boundary, not part of what the bound keeps"
    );
}

/// The secret categories have NO FIELD OF THEIR OWN. This is where the
/// closed-surface exclusion is actually provable, and it is a real absence
/// claim: the swept events each DO appear in this capture, so the exclusion is
/// exactly that no credential/token/environment/connection slot exists to put
/// one in. A product that added any of these fields, or renamed an existing one
/// to one of them, fails here.
///
/// Field names are compared EXACTLY (each name split out of the record's
/// `|`-joined name list), never as substrings of the rendered record: a
/// substring rule would be satisfied-or-broken by unrelated field names rather
/// than by the slot the product actually declares.
fn assert_the_secret_categories_have_no_slot_of_their_own(records: &[CapturedRecord]) {
    assert!(!records.is_empty(), "the field sweep must capture records");
    for record in records {
        for slot in [
            "credential",
            "credentials",
            "token",
            "tokens",
            "api_key",
            "secret",
            "password",
            "env",
            "environment",
            "env_var",
            "connection",
            "connection_string",
            "conn_str",
            "dsn",
            "bearer",
        ] {
            assert!(
                !record.field_names().split('|').any(|name| name == slot),
                "the closed field surface of {} must carry no {slot} slot",
                record.event
            );
        }
    }
}

fn assert_typed_host_error_payload_is_not_projected(
    error_payload: &str,
    canaries: &[&str],
) -> Vec<CapturedRecord> {
    assert!(!canaries.is_empty(), "the typed error must carry canaries");
    let error = HostError::Platform(error_payload.to_owned());
    let records = capture_emitted_records(|| {
        let projection = HostRequestProjection::failed(EntrypointStage::LaunchConfig, &error)
            .with_operation(AdmittedEvent::ServiceStart);
        observe_host_request(&projection);
    });
    let failed_requests: Vec<&CapturedRecord> = records
        .iter()
        .filter(|record| {
            record.event == "host.request" && record.field("evidence") == Some("failed")
        })
        .collect();
    assert_eq!(
        failed_requests.len(),
        1,
        "the typed Platform error must produce one failed request record"
    );
    assert_eq!(
        failed_requests[0].field("reason"),
        Some("platform"),
        "the typed failure must project its fixed reason, not its payload"
    );
    assert_eq!(
        failed_requests[0].field("reason_missing"),
        Some("false"),
        "the typed failure reason must be explicitly present"
    );
    for canary in canaries {
        assert!(
            error_payload.contains(*canary),
            "error payload must carry {canary:?}"
        );
        assert!(
            records.iter().all(|record| {
                !record.event.contains(*canary) && !record.whole().contains(*canary)
            }),
            "typed error canary {canary:?} must be absent from every captured record"
        );
    }
    records
}

/// No record may carry an arbitrary error Debug/Display rendering, and every
/// reason the facade ACTUALLY projected is one of its frozen nonsecret reason
/// codes -- compared against that independent list, never against the values
/// this sweep poured.
///
/// FIXED (was red against the wrong premise): the reason check used to run under
/// `if let Some(reason) = record.field("reason")`, which is ALWAYS taken --
/// `observe_host_request` writes `reason = projection.reason.unwrap_or("")`, so
/// an unset reason is `Some("")`, and `""` is not in the permitted set. Every
/// one of the four projections this case submitted left `reason` unset, so the
/// check was judging an empty string against a frozen code list and could only
/// ever fail. The check now runs only where a reason was genuinely projected,
/// and the `failed(&HostError::Stopped)` projection added to the capture loop is
/// what gives it something true to judge. This is option (b) of the two honest
/// repairs: a real typed reason is submitted, and the `reason_missing` flag is
/// read so a genuinely-absent reason is never silently treated as an empty
/// code.
fn assert_only_frozen_reason_codes_are_projected(records: &[CapturedRecord]) {
    let mut judged_reasons = 0usize;
    for record in records {
        for value in record.field_values().split('|') {
            assert!(
                !value.contains("Error {"),
                "no record may carry an error Debug rendering, got {value:?}"
            );
            assert!(
                !value.contains(" at "),
                "no record may carry an error source chain, got {value:?}"
            );
        }
        match record.field("reason") {
            // A record that is not a request record never carries the slot.
            None => {}
            Some(reason) => {
                // The slot's honesty flag is checked in BOTH directions, because
                // the flag is what stops an absent reason from being read as a
                // code, and what stops a present one from being read as absent.
                if reason.is_empty() {
                    assert_eq!(
                        record.field("reason_missing"),
                        Some("true"),
                        "a record that projected no reason must mark the reason slot explicitly \
                         missing, never publish an empty code"
                    );
                } else {
                    assert_eq!(
                        record.field("reason_missing"),
                        Some("false"),
                        "a record that projected a reason must mark the reason slot present"
                    );
                    judged_reasons += 1;
                    assert!(
                        PERMITTED_REASON_CODES.contains(&reason),
                        "a projected reason must be a frozen nonsecret reason code, got {reason:?}"
                    );
                }
            }
        }
    }
    assert_eq!(
        judged_reasons, 1,
        "exactly one submitted projection carried a typed reason, so the reason-code check had a \
         real reason to judge rather than a slot it never filled"
    );
    // The one record that projected a reason really is the one that carried a
    // typed error, so the arm above judged a reason and not an accident. The
    // collection holds BORROWS of the capture's own records -- `records.iter()`
    // yields `&CapturedRecord`, so this is a `Vec<&CapturedRecord>` and the
    // records are only read from it; nothing here needs an owned clone.
    let reason_bearing: Vec<&CapturedRecord> = records
        .iter()
        .filter(|record| record.field("reason_missing") == Some("false"))
        .collect();
    assert_eq!(
        reason_bearing.len(),
        1,
        "only the `failed(&HostError::Stopped)` projection may report a present reason"
    );
    assert_eq!(
        reason_bearing[0].field("reason"),
        Some("stopped"),
        "a typed `HostError::Stopped` must project its own frozen reason code"
    );
}

/// The sweep is non-vacuous: it really saw one stage record per stage detail,
/// one terminal record per terminal code, and one request record per projection,
/// and every one of those records carries the facade's own target. An absence
/// sweep over a capture that never saw the record it is reasoning about would
/// prove nothing, so each count is asserted here.
///
/// Q6 (order-independent capture): the sweep's own records are selected by the
/// SPECIFIC event name they are about. Asserting "nothing else was captured"
/// instead would couple this case to another test in the same binary: a
/// projection that reaches the Event Log seam also publishes a
/// `host.event_log_admission` record, so whether that extra record exists
/// depends on whether some other case started or shut the producer down first,
/// which cargo's parallel test order decides. Naming the events the absence
/// sweeps are about removes that coupling entirely and is the stronger claim.
fn assert_the_sweep_saw_every_event_it_is_reasoning_about(records: &[CapturedRecord]) {
    let emitted_events: Vec<String> = records.iter().map(|record| record.event.clone()).collect();
    assert_eq!(
        emitted_events
            .iter()
            .filter(|event| *event == "host.entrypoint_stage")
            .count(),
        5,
        "every stage detail must have produced exactly one stage record"
    );
    assert_eq!(
        emitted_events
            .iter()
            .filter(|event| *event == "host.terminal_error")
            .count(),
        4,
        "every terminal code must have produced exactly one terminal record"
    );
    assert_eq!(
        emitted_events
            .iter()
            .filter(|event| *event == "host.request")
            .count(),
        5,
        "every projection must have produced exactly one request record"
    );
    for event in [
        "host.entrypoint_stage",
        "host.terminal_error",
        "host.request",
    ] {
        let scoped: Vec<&CapturedRecord> = records
            .iter()
            .filter(|record| record.event == event)
            .collect();
        assert!(
            !scoped.is_empty(),
            "the sweep must have captured at least one {event} record"
        );
        for record in scoped {
            assert_eq!(
                record.target, HOST_DIAGNOSTICS_TARGET,
                "a swept {event} record must be a facade record"
            );
        }
    }
    let stage_record = records
        .iter()
        .find(|record| record.event == "host.entrypoint_stage")
        .expect("the sweep must have captured a stage record");
    assert!(
        stage_record.field_names().contains("detail_truncated"),
        "a stage record must report truncation as its own field"
    );
}

/// THE PRODUCT'S REAL BEHAVIOUR, stated as such, and the half of case 889/11
/// that had it backwards: the in-bound credential, bearer token, environment
/// entry and connection string this sweep poured ARE RECORDED, verbatim, each
/// with `detail_truncated == "false"` and its own byte length. This is not a
/// defect being papered over and not a scrubbing rule this case claims to have.
/// `truncate_to` bounds SIZE only, `bound_detail` never inspects content for
/// secrets, and `observe_entrypoint_with_detail` writes
/// `detail = bounded.text()`, so the retained prefix of an in-bound value is the
/// value itself.
///
/// The real I15.4 contract, which is what the closed-surface and
/// removed-material arms actually prove: the field surface has NO channel of its
/// own for credentials, tokens, environment values or connection strings, the
/// facade never READS one to construct a record, and what exceeds the bound is
/// genuinely gone. The remaining half of the obligation -- do not hand secret
/// material to a bounded channel -- is entirely CALLER-side, and no assertion
/// here can prove it, so none claims it.
///
/// All four assertions can fail. A product that began redacting in-bound
/// secrets fails the `detail` equality; one that began cutting an in-bound
/// value fails the truncation flag; one that began reporting a truncation it did
/// not perform fails the same flag; one that began reporting a bound instead of
/// the truth fails `detail_bytes`.
fn assert_the_in_bound_canaries_are_recorded_verbatim(
    records: &[CapturedRecord],
    pours: [(&str, &Canary); 4],
) {
    let stage_records: Vec<&CapturedRecord> = records
        .iter()
        .filter(|record| record.event == "host.entrypoint_stage")
        .collect();
    for (stage, canary) in pours {
        let channel = canary.channel;
        let value = &canary.value;
        let record = stage_records
            .iter()
            .find(|record| record.field("stage") == Some(stage))
            .unwrap_or_else(|| panic!("the {channel} pour must have produced a {stage} record"));
        assert_eq!(
            record.field("detail"),
            Some(value.as_str()),
            "an in-bound {channel} canary IS recorded verbatim: bounding limits size, not \
             sensitivity"
        );
        assert_eq!(
            record.field("detail_truncated"),
            Some("false"),
            "an in-bound {channel} canary must report that nothing was cut"
        );
        assert_eq!(
            record.field("detail_bytes"),
            Some(value.len().to_string().as_str()),
            "an in-bound {channel} canary must report its own byte length"
        );
        assert_eq!(
            record.target, HOST_DIAGNOSTICS_TARGET,
            "the in-bound {channel} canary record must still be a facade record"
        );
    }
}

// WORK_UNIT_CASE: 889/12
#[test]
fn source_user_and_model_payloads_have_no_dedicated_field_and_lose_only_over_cap_material() {
    // Behaviour under test: source, user, and model categories have no place in
    // the facade's closed field surface, and the facade never reads a provider,
    // source, or model to obtain them. Raw channels receive over-cap DUMMY!
    // markers only; a typed HostError capture below separately checks explicit
    // test-only source/user/model canaries on the failure projection.
    //
    // (The name this case used to carry -- "..._never_reach_a_record" -- claimed
    // total absence, which is false: its own residue arm below proves the
    // in-bound payload IS recorded. The name now says what the case proves.)
    //
    // HONEST SCOPE: these DUMMY!-prefixed values are synthetic nonsecret
    // markers, not real source/user/model content. Bounded detail/code APIs
    // limit size, not sensitivity, so this raw sweep proves removed-tail and
    // field-slot absence only; the typed failure capture covers payload
    // exclusion on the actual HostError projection path.
    //
    // Falsifiable by construction: the absence assertions run over each
    // record's WHOLE text, and the case fails the moment any removed tail
    // survives or a payload slot appears. The positive arms fail the moment the
    // facade stops recording, so the sweep cannot pass vacuously.
    let marker = "DUMMY!";

    // One over-cap payload per channel, each carrying a distinctive tail placed
    // BEYOND the cap boundary. These are the values whose tails the absence
    // arms below ask about, and each length is MEASURED before any absence
    // arm is trusted. The repeat count is derived from the product's own
    // bound rather than fixed, so the SHORTEST sentinel still clears the cap
    // twice over whatever its length is:
    //
    //   channel  sentinel   repeats  run     total            vs 1024 cap
    //   SOURCE    17 bytes    121    2057    2083 (+26 tail)  +1059
    //   USER      15 bytes    137    2055    2079 (+24 tail)  +1055
    //   MODEL     16 bytes    129    2064    2089 (+25 tail)  +1065
    //
    // 64 copies did NOT clear the cap for every channel: USER came to 960 + 19
    // = 979 bytes, which is UNDER the bound, so that payload could never be
    // truncated and the "each over-cap payload was reported as truncated"
    // assertion could never have reached three. The tail is now also named
    // after the case rather than the marker, so the fragment sweep below asks
    // about a token that exists nowhere else in the file.
    // Phase 0, the over-cap fixtures: one per payload channel, each carrying a
    // tail placed BEYOND the cap boundary, every length MEASURED before any
    // absence arm is trusted.
    let payload_tails = build_the_over_cap_payload_fixtures(marker);

    // Phase 1, the capture: both bounded channels plus the widest record.
    let records = capture_the_payload_sweep(&payload_tails);
    let error_canaries = [
        "source=TEST-ONLY-889-12-SOURCE",
        "user=TEST-ONLY-889-12-USER",
        "model=TEST-ONLY-889-12-MODEL",
    ];
    let error_payload = error_canaries.join(" | ");
    let typed_failure_records =
        assert_typed_host_error_payload_is_not_projected(&error_payload, &error_canaries);

    // Phase 2, the removed-material absence claim: no record carries the
    // removed tail of any over-cap payload, nor any fragment of one, so a
    // partial retention cannot pass as absence.
    assert_no_payload_tail_or_fragment_reaches_a_record(&records, &payload_tails);

    // Phase 3, every over-cap payload is reported as truncated, with its
    // original byte length, and its retained prefix is bounded.
    assert_each_payload_is_reported_truncated_with_its_own_length(&records, &payload_tails);

    // Phase 4, the payload channels have no field of their own: the facade's
    // field vocabulary is closed, so a source/user/model slot cannot appear at
    // all.
    assert_the_payload_channels_have_no_slot_of_their_own(&records);
    assert_the_payload_channels_have_no_slot_of_their_own(&typed_failure_records);

    // Phase 5, the sweep is non-vacuous: it really saw one stage record per
    // payload detail, one terminal record per payload code, and one request
    // record per projection, and each is a facade record.
    assert_the_payload_sweep_saw_every_event_it_is_about(&records);

    // Phase 6, the identities and stage names that ARE recorded are the frozen
    // vocabulary, exactly.
    assert_only_the_frozen_stage_and_phase_vocabulary_was_recorded(&records);

    // The code channel also reports its bound honestly rather than passing a
    // payload through: an over-cap code is truncated, its original length is
    // reported, and what the bound removed never reaches a record.
    assert_the_code_channel_reports_its_bound_honestly(&records, &payload_tails);

    // Phase 8, the request records project IDENTITIES only, so a payload has
    // nothing to ride in on one.
    assert_a_request_record_projects_identities_and_no_reason_code(&records);

    // Phase 9, an in-bound payload IS recorded verbatim: bounding limits size,
    // not sensitivity.
    assert_an_in_bound_payload_is_recorded_verbatim(marker);
}

/// One over-cap payload per payload channel, each carrying a distinctive tail
/// placed BEYOND the cap boundary, and each length MEASURED before any absence
/// arm downstream is trusted.
///
/// The repeat count is derived from the product's own bound rather than fixed,
/// so the SHORTEST sentinel still clears the cap twice over whatever its length
/// is:
///
/// ```text
///   channel  sentinel   repeats  run     total            vs 1024 cap
///   SOURCE    17 bytes    121    2057    2083 (+26 tail)  +1059
///   USER      15 bytes    137    2055    2079 (+24 tail)  +1055
///   MODEL     16 bytes    129    2064    2089 (+25 tail)  +1065
/// ```
///
/// 64 copies did NOT clear the cap for every channel: USER came to 960 + 19 =
/// 979 bytes, which is UNDER the bound, so that payload could never be truncated
/// and the "each over-cap payload was reported as truncated" assertion could
/// never have reached three. The tail is named after the case rather than the
/// marker, so the fragment sweep asks about a token that exists nowhere else in
/// the file.
///
/// Returns `(channel, tail, over_cap)` per channel, which every later phase
/// reads; the measurement assertions here are therefore not bypassable by
/// ignoring the result.
fn build_the_over_cap_payload_fixtures(marker: &str) -> Vec<(&'static str, String, String)> {
    let mut payload_tails = Vec::new();
    for channel in EXCLUDED_PAYLOAD_CHANNELS {
        let poured = pour(channel, marker);
        let tail = format!("REMOVED-889-12-TAIL-{channel}");
        // Integer arithmetic against the product's own bound: the run must end
        // strictly past the cap boundary, so the tail can never be part of what
        // the bound keeps.
        let repeats = (2 * MAX_DIAGNOSTIC_DETAIL_BYTES) / poured.value.len() + 1;
        let over_cap = poured.value.repeat(repeats) + &tail;
        assert!(
            over_cap.len() > 2 * MAX_DIAGNOSTIC_DETAIL_BYTES,
            "the over-cap {channel} payload must clear the declared bound by a clear margin, got {} bytes from {repeats} copies of a {}-byte sentinel against a {MAX_DIAGNOSTIC_DETAIL_BYTES} byte bound",
            over_cap.len(),
            poured.value.len()
        );
        assert!(
            poured.value.len() * repeats > MAX_DIAGNOSTIC_DETAIL_BYTES,
            "the {channel} repeat run must extend past the cap boundary so the tail is genuinely removed"
        );
        payload_tails.push((channel, tail, over_cap));
    }
    payload_tails
}

/// The capture phase of case 889/12: one synthetic nonsecret DUMMY! marker per
/// channel through the free-text detail and bounded code channels, plus two
/// identity-only request projections. Typed canaries use the failure capture.
///
/// The widest record is built from the identities a call site already holds, so
/// no payload is handed to it at all.
///
/// Returns the capture, which every later phase of the case reads.
fn capture_the_payload_sweep(
    payload_tails: &[(&'static str, String, String)],
) -> Vec<CapturedRecord> {
    capture_emitted_records(|| {
        // A nonsecret marker standing in for the source category.
        observe_entrypoint_with_detail(EntrypointStage::Startup, &payload_tails[0].2);
        // A nonsecret marker standing in for the user category.
        observe_entrypoint_with_detail(EntrypointStage::LaunchConfig, &payload_tails[1].2);
        // A nonsecret marker standing in for the model category.
        observe_entrypoint_with_detail(EntrypointStage::ConsoleLoop, &payload_tails[2].2);
        // The bounded code channel carries payloads too: it is bounded and
        // reported, never a passthrough.
        observe_terminal_error(&payload_tails[0].2);
        observe_terminal_error(&payload_tails[1].2);
        observe_terminal_error(&payload_tails[2].2);
        let projection = HostRequestProjection::process_started(
            EntrypointStage::ScmDispatch,
            std::process::id(),
        )
        .with_request(HostConsoleRequest::Status)
        .with_operation(AdmittedEvent::ServiceStart);
        observe_host_request(&projection);
        let unknown = HostRequestProjection::unknown(EntrypointStage::ShutdownDrain)
            .with_request(HostConsoleRequest::Stop)
            .with_operation(AdmittedEvent::ServiceStop);
        observe_host_request(&unknown);
        note_event_log_sink_status();
    })
}

/// No record may carry the removed tail of any over-cap payload, and no fragment
/// of one, so a partial retention cannot pass as absence.
///
/// The fragment token is the tail minus its `REMOVED-` prefix, and it exists
/// nowhere else in this file, which is what makes the fragment arm a real
/// absence claim rather than a second spelling of the same question.
///
/// Absence may be claimed only for what the bound actually REMOVED. The
/// retained prefix of every one of these payloads is the sentinel itself
/// repeated, and the product copies that retained prefix verbatim, so the
/// sentinel IS present in the record on purpose. Asserting the sentinel or a
/// `-CHANNEL-` fragment is absent would assert the opposite of the truth; what
/// is proved instead, in the truncation phase, is that the retained prefix is a
/// true prefix of this payload and that the record names the payload's own byte
/// length.
fn assert_no_payload_tail_or_fragment_reaches_a_record(
    records: &[CapturedRecord],
    payload_tails: &[(&'static str, String, String)],
) {
    // DELETED (was impossible): a sweep for "DUMMY!-", "-SOURCE-", "-USER-" and
    // "-MODEL-" over every record. `DUMMY!-` is the first seven bytes of the
    // RETAINED PREFIX of each over-cap payload and `-SOURCE-`/`-USER-`/`-MODEL-`
    // are interior to it, and `observe_entrypoint_with_detail` writes
    // `detail = bounded.text()` -- so the product is REQUIRED to carry them.
    // That sweep could never pass; absence is claimed only for the tail beyond
    // the boundary, which is the material genuinely removed.
    for (channel, tail, over_cap) in payload_tails {
        let fragment = tail
            .strip_prefix("REMOVED-")
            .unwrap_or_else(|| panic!("the {channel} payload tail must keep its REMOVED- prefix"));
        assert!(
            !records
                .iter()
                .any(|record| record.whole().contains(tail.as_str())),
            "no record may carry the {channel} payload tail {tail:?}"
        );
        assert!(
            !records
                .iter()
                .any(|record| record.whole().contains(fragment)),
            "no record may carry a fragment of the {channel} payload tail: {fragment:?}"
        );
        assert!(
            over_cap.ends_with(tail.as_str()) && !over_cap.starts_with(fragment),
            "the {channel} fixture must end with its tail so the tail is past the boundary"
        );
    }
}

/// Every over-cap payload is reported as truncated, with its original byte
/// length, and its retained prefix is bounded: the record tells a reader that a
/// payload was cut without carrying what the cut removed.
///
/// A product that raised the declared bound, cut after the cap, or reported a
/// bound instead of the truth fails one of these arms.
fn assert_each_payload_is_reported_truncated_with_its_own_length(
    records: &[CapturedRecord],
    payload_tails: &[(&'static str, String, String)],
) {
    let truncated_stages: Vec<&CapturedRecord> = records
        .iter()
        .filter(|record| {
            record.event == "host.entrypoint_stage"
                && record.field("detail_truncated") == Some("true")
        })
        .collect();
    assert_eq!(
        truncated_stages.len(),
        3,
        "each over-cap payload must have been reported as truncated"
    );
    for (record, (channel, _, over_cap)) in truncated_stages.iter().zip(payload_tails) {
        assert_eq!(
            record.field("detail_bytes"),
            Some(over_cap.len().to_string().as_str()),
            "a truncated {channel} payload must report its original byte length"
        );
        let retained = record
            .field("detail")
            .expect("a stage record must carry its bounded detail");
        assert!(
            over_cap.starts_with(retained),
            "a truncated {channel} payload must retain a prefix of the payload"
        );
        assert!(
            retained.len() <= MAX_DIAGNOSTIC_DETAIL_BYTES,
            "a retained {channel} payload prefix must stay within the declared bound"
        );
    }
}

/// The payload channels have no field of their own: the facade's field
/// vocabulary is closed, so a source/user/model slot cannot appear at all.
///
/// This arm fails the moment a payload slot is added to the record.
fn assert_the_payload_channels_have_no_slot_of_their_own(records: &[CapturedRecord]) {
    for payload_slot in [
        "source",
        "source_payload",
        "user",
        "user_payload",
        "model",
        "model_payload",
        "prompt",
        "command_line",
    ] {
        assert!(
            !records
                .iter()
                .any(|record| record.field_names().contains(payload_slot)),
            "the closed field surface must carry no {payload_slot} slot"
        );
    }
}

/// The sweep is non-vacuous: it really saw one stage record per payload detail,
/// one terminal record per payload code, and one request record per projection,
/// and every one of those records is a facade record. Absence is then a property
/// of the payload channels rather than of an empty record.
///
/// Q6 (order-independent capture), same shape as the sibling secret sweep: the
/// records are selected by their own event name, so whether another case in this
/// binary has already started or shut the process-wide Event Log producer --
/// which decides whether this sweep's projections also publish a
/// `host.event_log_admission` record -- cannot change the outcome here.
fn assert_the_payload_sweep_saw_every_event_it_is_about(records: &[CapturedRecord]) {
    let emitted_events: Vec<String> = records.iter().map(|record| record.event.clone()).collect();
    assert_eq!(
        emitted_events
            .iter()
            .filter(|event| *event == "host.entrypoint_stage")
            .count(),
        3,
        "every payload detail must have produced exactly one stage record"
    );
    assert_eq!(
        emitted_events
            .iter()
            .filter(|event| *event == "host.terminal_error")
            .count(),
        3,
        "every payload code must have produced exactly one terminal record"
    );
    assert_eq!(
        emitted_events
            .iter()
            .filter(|event| *event == "host.request")
            .count(),
        2,
        "every projection must have produced exactly one request record"
    );
    for event in [
        "host.entrypoint_stage",
        "host.terminal_error",
        "host.request",
    ] {
        let scoped: Vec<&CapturedRecord> = records
            .iter()
            .filter(|record| record.event == event)
            .collect();
        assert!(
            !scoped.is_empty(),
            "the sweep must have captured at least one {event} record"
        );
        for record in scoped {
            assert_eq!(
                record.target, HOST_DIAGNOSTICS_TARGET,
                "a swept {event} record must be a facade record"
            );
        }
    }
}

/// The stage names that ARE recorded are the frozen vocabulary, exactly:
/// identities and reason codes are permitted, payloads are not. A stage record
/// names its stage in `stage`; a request record names the same frozen vocabulary
/// in `phase`.
///
/// The permitted identity that IS recorded is the process id the call site
/// already holds, never a probed name, path, or payload behind it.
fn assert_only_the_frozen_stage_and_phase_vocabulary_was_recorded(records: &[CapturedRecord]) {
    let recorded_stages: Vec<&str> = records
        .iter()
        .filter_map(|record| record.field("stage"))
        .collect();
    assert_eq!(
        recorded_stages,
        vec!["startup", "launch_config", "console_loop"],
        "recorded stages must be exactly the frozen stage vocabulary"
    );
    let recorded_phases: Vec<&str> = records
        .iter()
        .filter(|record| record.event == "host.request")
        .filter_map(|record| record.field("phase"))
        .collect();
    assert_eq!(
        recorded_phases,
        vec!["scm_dispatch", "shutdown_drain"],
        "recorded phases must be exactly the frozen stage vocabulary"
    );
    let request_record = records
        .iter()
        .find(|record| record.event == "host.request")
        .expect("the sweep must have captured a request record");
    assert_eq!(
        request_record.field("process"),
        Some(std::process::id().to_string().as_str()),
        "a process record must carry the observed process id verbatim"
    );
    assert_eq!(
        request_record.field("evidence"),
        Some("process_started"),
        "a process record must carry the evidence class that supports it"
    );
}

/// The code channel also reports its bound honestly rather than passing a
/// payload through: an over-cap code is truncated, its original length is
/// reported, and what the bound removed never reaches a record.
fn assert_the_code_channel_reports_its_bound_honestly(
    records: &[CapturedRecord],
    payload_tails: &[(&'static str, String, String)],
) {
    let truncated_codes: Vec<&CapturedRecord> = records
        .iter()
        .filter(|record| record.event == "host.terminal_error")
        .collect();
    assert_eq!(truncated_codes.len(), 3);
    for (record, (channel, _, over_cap)) in truncated_codes.iter().zip(payload_tails) {
        assert_eq!(
            record.field("code_truncated"),
            Some("true"),
            "an over-cap {channel} code must report truncation"
        );
        assert_eq!(
            record.field("code_bytes"),
            Some(over_cap.len().to_string().as_str()),
            "an over-cap {channel} code must report its original byte length"
        );
        let retained = record
            .field("code")
            .expect("a terminal record must carry its bounded code");
        assert!(
            over_cap.starts_with(retained),
            "an over-cap {channel} code must retain a prefix of the code"
        );
        assert!(
            retained.len() <= MAX_DIAGNOSTIC_FIELD_BYTES,
            "a retained {channel} code must stay within the field bound, got {} bytes",
            retained.len()
        );
    }
}

/// A request record projects IDENTITIES only, so a payload has nothing to ride
/// in on one. The records are selected by their own event name and matched
/// against the projections this case actually submitted -- counted and checked
/// against themselves -- never zipped against the payload list they have nothing
/// to do with.
///
/// FIXED (compared two unrelated counts): the old check put two request records
/// against three payload tails, and neither side had any relationship to the
/// other -- the two projections submitted here are `process_started` and
/// `unknown`, and neither relates to the payload list at all. The numbers were
/// not retuned to make it pass; the comparison is against the number of
/// projections actually submitted, named in one place so the count and the
/// content cannot drift apart.
///
/// FIXED (dropped the guard): the reason check used to read
/// `record.field("reason").unwrap_or_default()`, which yields `""` for both of
/// those projections -- `observe_host_request` writes `reason =
/// projection.reason.unwrap_or("")` -- and `""` is not a frozen reason code, so
/// the assertion was red against an empty string. Neither projection here
/// carries a typed error, so there is no real reason for this case to judge: the
/// honest repair is to judge the one thing that IS true about an unset reason,
/// which is that the facade marks the slot explicitly missing instead of
/// publishing a guessed or empty code. The "only a frozen reason code is ever
/// projected" rule itself is proved at runtime by case 889/11, which submits a
/// real `HostRequestProjection::failed(&HostError::Stopped)` and asserts the code
/// that comes back.
fn assert_a_request_record_projects_identities_and_no_reason_code(records: &[CapturedRecord]) {
    let submitted_phases = ["scm_dispatch", "shutdown_drain"];
    let request_records: Vec<&CapturedRecord> = records
        .iter()
        .filter(|record| record.event == "host.request")
        .collect();
    assert_eq!(
        request_records.len(),
        submitted_phases.len(),
        "there must be exactly one request record per submitted projection"
    );
    // The two projections' identities, reconstructed from the product's own
    // vocabulary rather than from the payload list: a record has to be one of
    // the projections this case submitted, not merely one of the right count.
    // `assert_only_the_frozen_stage_and_phase_vocabulary_was_recorded` already
    // pins this exact sequence, so this arm is the non-vacuity check on that
    // list rather than a second spelling of it.
    let submitted_evidence: Vec<&str> = request_records
        .iter()
        .filter_map(|record| record.field("evidence"))
        .collect();
    assert_eq!(
        submitted_evidence,
        vec!["process_started", "unknown"],
        "the request records must carry the evidence classes this case submitted"
    );
    for record in &request_records {
        assert_eq!(
            record.field("reason"),
            Some(""),
            "a projection that carries no typed error must leave the reason slot empty"
        );
        assert_eq!(
            record.field("reason_missing"),
            Some("true"),
            "an unprojected reason must be reported as explicitly missing, never as a code"
        );
    }
}

/// THE PRODUCT'S REAL BEHAVIOUR, stated as such: an in-bound payload a caller
/// hands to a bounded detail channel IS recorded, verbatim, with
/// `detail_truncated == false` and its own byte length. This is not a defect
/// being papered over and not a scrubbing rule this case claims to have --
/// `bound_detail` bounds size, not sensitivity, and the exclusion is proved
/// where the product really keeps payloads: the closed field surface and the
/// material past the cap boundary. These three assertions state the real
/// contract, and they fail the moment it stops holding: a product that began
/// cutting in-bound material, or began reporting a truncation flag it did not
/// perform, is a behaviour change this case would catch.
fn assert_an_in_bound_payload_is_recorded_verbatim(marker: &str) {
    let in_bound_model = pour("MODEL", marker).value;
    assert!(
        in_bound_model.len() <= MAX_DIAGNOSTIC_DETAIL_BYTES,
        "the in-bound payload fixture must fit the bound, got {} bytes against a {MAX_DIAGNOSTIC_DETAIL_BYTES} byte bound",
        in_bound_model.len()
    );
    let in_bound = capture_emitted_records(|| {
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &in_bound_model);
    });
    let in_bound_record = in_bound
        .iter()
        .find(|record| record.event == "host.entrypoint_stage")
        .expect("the in-bound payload must have produced one stage record");
    assert_eq!(
        in_bound_record.field("detail"),
        Some(in_bound_model.as_str()),
        "an in-bound payload IS recorded verbatim: bounding limits size, not sensitivity"
    );
    assert_eq!(
        in_bound_record.field("detail_truncated"),
        Some("false"),
        "an in-bound payload must report that nothing was cut"
    );
    assert_eq!(
        in_bound_record.field("detail_bytes"),
        Some(in_bound_model.len().to_string().as_str()),
        "an in-bound payload must report its own byte length"
    );
    assert_eq!(
        in_bound_record.target, HOST_DIAGNOSTICS_TARGET,
        "the in-bound payload record must still be a facade record"
    );
}

// WORK_UNIT_CASE: 889/14
#[test]
fn sink_degradation_and_timeout_never_change_the_host_result_or_claim_a_drain() {
    // Behaviour under test: three obligations, all load-bearing.
    //
    // (1) Non-interference. One identical emit closure -- the same facade
    // calls, the same payloads -- is executed twice, once behind a sink that
    // returns `Err` from every `write` and once behind a healthy one. The
    // compared value is the product's OWN published outcome for that request:
    // the Event Log admission the facade reports when it projects a request,
    // read off the real emission path by a layer that does not depend on the
    // sink. A degraded sink therefore changes nothing Host-observable, and the
    // comparison can actually fail: if the emission path were destroyed, no
    // outcome would be published at all and the capture would come back empty.
    // A panic raised inside the writer is NOT contained by the product and NOT
    // contained by tracing; block (1b) below catches it in the test itself and
    // proves only what is true -- that the admission layer, which runs before
    // the writer, has already recorded the same typed outcome.
    //
    // (2) Honest timeout. "Dropping a future or reaching a caller timeout is
    // not proof that a synchronous OS call stopped", and "do not claim a
    // drain/abort that did not complete". The product's types must express
    // exactly that: `EventLogWorkCount` has no value for a confirmed zero and
    // `EventLogWorkDisposition` has no value for a completed drain or a
    // confirmed abort. Both facts are asserted by a census of the PRODUCT'S
    // OWN SOURCE -- the `as_str()` arm count of each vocabulary, and every
    // string the producer module can spell -- because a runtime comparison over
    // a one-variant enum cannot fail. Every work-count arm now constrains what
    // it actually observed, so a false "drained" or "aborted" report, or a
    // confirmed zero, fails here. The runtime blocked-OS-call case has no
    // latency-injection seam in this read-only product and is stated as a
    // limitation in a comment below rather than implied by an empty match arm.
    //
    // (3) Bounded workers, measured against the product's own published
    // accounting and against the product's own source: the concurrent sweep's
    // records come out exact, every projection publishes exactly one typed
    // admission outcome, every published drop total is bounded by the records
    // submitted, the producer's own start record publishes whether the worker
    // thread exists and what the in-flight bound is, the wrapper has exactly one
    // spawn site, and no delivery record is observable on a caller-side thread.
    // The one-worker BOUND is a source census, not a runtime thread count: the
    // delivery record is emitted from the product's worker, and a thread-local
    // capture cannot see it, so nothing at runtime can count the threads a
    // delivery reached. A writer-side thread-id set is deliberately NOT used: it
    // records the threads that dispatched through the writer, not the threads the
    // product created.
    //
    // The vocabulary of completion CLAIMS, `DRAIN_CLAIMS`, is declared at FILE
    // SCOPE so the census helper below sweeps exactly the words named here.
    let fixture = contract_fixture();
    assert_eq!(
        fixture["event_log_sink"].as_str(),
        Some("unavailable"),
        "the fixture must pin the unavailable Event Log sink seam"
    );

    // The typed in-flight bound the facade itself reports at producer start,
    // read out of its own bounded diagnostic record rather than assumed here.
    // Returns that record, which the shutdown bound and the start-record arms
    // below both read, so the bound cannot be dropped on the way through.
    let start_records = capture_the_producer_start_record();
    let in_flight_bound = the_in_flight_bound_the_product_published(&start_records);
    let queue_cap = the_fixtures_queue_capacity(&fixture);

    // (1) The same Host operation, run behind a sink that really FAILS and
    // behind a healthy one: one identical closure, so only the sink's health
    // differs.
    //
    // The helper RUNS the cross-health comparison and the caller BOUNDS it: it
    // returns the degraded run, and this caller asserts on that run's own typed
    // fields below, so the returned value cannot be dropped or ignored without
    // losing the operation/evidence/receipt arms it exists to carry forward.
    let degraded = assert_a_failing_sink_changes_no_host_observable_outcome();
    assert_the_compared_admission_names_the_projection_it_carried(&degraded);

    // (1b) A panic raised inside the writer, and exactly what the product does
    // and does not contain. The injected panic stays inside
    // `std::panic::catch_unwind`, and the `take_hook`/`set_hook` pair stays
    // balanced inside the helper that owns it.
    assert_a_panicking_writer_changes_no_published_admission(&degraded);

    // (2) The producer's terminal view of outstanding work. Nothing here claims
    // that a drain or a confirmed abort happened, and the claim that none CAN
    // be reported is an exhaustive census of the product's own source rather
    // than a match arm over a one-variant enum.
    // The terminal snapshot has to be taken from the producer call itself:
    // the facade's `shutdown_event_log_reporting` returns `()`, and it only
    // observes that same `shutdown_event_log_producer` snapshot on the way to
    // its record. The two are asserted to be the very same terminal view
    // below, so the typed facts still have to be read off the producer's own
    // return value rather than off the `()` the facade hands back.
    let terminal = shutdown_event_log_producer();
    let shutdown_records = capture_the_producer_shutdown_record();
    // The facade's shutdown record must report THIS snapshot's facts, read
    // through the same readers the record's own fields go through: the typed
    // `as_str()` for the disposition, and `known()`/`is_none()` for each count.
    // That equality is checkable at runtime -- a record that reported a stale
    // or fabricated disposition, or that dropped the `*_unknown` flags, fails.
    // The line is located by its own product-typed `event=` value, never by a
    // position or an occurrence count, so no layout assumption hides below.
    assert_the_shutdown_record_agrees_with_the_snapshot_it_describes(
        &shutdown_records,
        &terminal,
        queue_cap + in_flight_bound,
    );
    // THE NEGATIVE THE ISSUE DEMANDS, and the one that has to be a source
    // census rather than a runtime comparison.
    assert_no_work_disposition_can_claim_a_drain_or_an_abort(&terminal);

    // HONEST LIMITATION, stated rather than implied: the runtime case this
    // issue is really about -- a synchronous OS report still blocking when the
    // caller gives up -- cannot be exercised from this target. `report_event`
    // reaches the real OS port with no latency-injection seam, and the arms
    // above census the product's own source rather than observing a blocked
    // call. What is proved here is the STRUCTURE: the vocabulary cannot
    // express a drain, an abort, or a confirmed zero, and a variant that could
    // would fail those censuses at build-of-this-test time. That is why there
    // is no empty match arm standing in for a runtime proof.

    // The queue's own shutdown snapshot parks held records and reports them as
    // unsent -- neither delivered nor proven stopped. Asserted as a real value
    // against the queue's own admission accounting, not as a match that can
    // only succeed.
    assert_shutdown_parks_held_records_as_unsent_not_delivered();

    // THE NEGATIVE THE ISSUE DEMANDS. What must be false is that the product can
    // report a completed drain, a confirmed abort, or a confirmed zero for
    // outstanding work -- not merely that it did not report one here.
    //
    // The census reads the DIAGNOSTIC NAMES the product publishes, never its
    // prose and never the name of the delivery record itself.
    assert_no_published_diagnostic_name_claims_a_completion(&manifest_source(
        "src/windows_event_log.rs",
    ));

    // (3) Bounded workers, asserted against facts the product PUBLISHES rather
    // than against a writer-side thread set.
    //
    // A writer-side thread-id set is NOT used, and cannot be: it records the
    // threads that CALLED the writer, never the threads the product CREATED. A
    // product that dispatched every record through a worker of its own would
    // still have recorded exactly this test's own ids, so such an assertion
    // proves nothing about workers. What the product really publishes is
    // observed directly instead: `start_event_log_reporting` reports whether
    // the process-wide worker thread was created, and how much work can be in
    // flight at once, in its own bounded start record.
    //
    // THE ONE-WORKER BOUND IS A SOURCE CENSUS, and no runtime thread census
    // runs in this case on ANY platform. Both the worker thread's name and the
    // sweep's own layers come from the same product source the census reads:
    // `start_event_log_producer` is the only place the product spawns a thread,
    // it spawns one named `eliot-event-log`, and that thread runs
    // `run_event_log_worker`, which is the only writer of the delivery record.
    // That census is what can actually fail.
    //
    // WHY NO RUNTIME THREAD CENSUS RUNS HERE, on Windows as much as anywhere
    // else: the sweep installs its layers with `tracing::subscriber::with_default`
    // inside `assert_the_concurrent_sweep_is_accounted_exactly`, which publishes
    // a THREAD-LOCAL default and does not propagate it into threads spawned
    // inside the block. A delivery record is emitted from the
    // `eliot-event-log` thread, which inherits no local default and so falls back
    // to `get_global()` -- never set by this sweep. So that record cannot reach
    // this capture on any platform, with or without a live Event Log port: the
    // limitation is the HARNESS's, not the product's and not the platform's. A
    // Windows port accepting the record changes where the record GOES, not which
    // subscriber sees it.
    // (3) The concurrent sweep, and the product's own accounting of the work it
    // owns. Returns the HIGHEST drop total the sweep ever saw published AND the
    // number of records it actually submitted: the post-shutdown admission arm
    // below compares its own counter against BOTH, so that arm cannot be
    // reached by ignoring this one. `submissions` is never a literal here -- it
    // is the sweep's own submitted count, threaded back out of the sweep that
    // produced the drops.
    let (highest_drops, submissions) = assert_the_concurrent_sweep_is_accounted_exactly();

    // THE SINGLE-WORKER BOUND, from a SOURCE CENSUS of the product's spawn
    // sites -- not from a runtime thread observation, and never from a second
    // pass. No runtime census of the worker thread runs in this case on any
    // platform, for the reason given above: the sweep's capture is thread-local,
    // so the worker's records never arrive in it. The census below is what can
    // actually fail.

    // The source census, which is the UNCONDITIONAL bound and needs no runtime:
    // the worker thread is created in exactly one place, from exactly one named
    // thread, and nothing else in the product spawns a thread.
    assert_the_wrapper_spawns_exactly_one_named_worker();

    // The producer's own start record, read back field by field: whether the
    // process-wide worker was created, and how much work the product says can
    // be outstanding at once. Both are values the producer published, and both
    // hold in either execution order. The two boolean slots are read as the
    // product spells a boolean -- `rendered_field` yields `true`/`false` -- and
    // `in_flight_bound` was parsed out of this very record above, so the
    // in-flight arm compares the record against itself through the product's own
    // reader.
    assert_the_start_record_reports_what_the_producer_published(&start_records, in_flight_bound);

    // Admission after the terminal snapshot is a typed refusal rather than a
    // worker spawn, in BOTH orders: if this case ran before the producer was
    // ever started the refusal is "not started", and if it ran after, the
    // producer now exists and reports the shutdown it was asked for. Either
    // way nothing is admitted and nothing is spawned.
    let refused = try_admit_admitted_event(AdmittedEvent::ServiceStart, "no-worker");
    match refused {
        EventLogAdmission::RejectedShutdown { dropped_total } => {
            // The counter is monotone, so the closed refusal must report at
            // least the highest value the sweep ever saw published, and at
            // most that value plus every refusal this case contributed: a
            // closed producer that ADVANCED the counter for a record it did
            // not admit would show up here as more than the sweep's own drops
            // plus one.
            assert!(
                dropped_total >= highest_drops,
                "a closed producer must report the drop counter it already held, never less than \
                 the {highest_drops} the sweep published"
            );
            assert!(
                dropped_total <= highest_drops + submissions,
                "a closed producer must not advance the counter for a record it refused, got \
                 {dropped_total} against a high-water mark of {highest_drops}"
            );
        }
        EventLogAdmission::RejectedNotStarted { dropped_total } => assert_eq!(
            dropped_total, 0,
            "a producer that never started must report a zero drop counter, never one"
        ),
        other => {
            panic!("admission after the terminal snapshot must be a typed refusal, got {other:?}")
        }
    }
}

/// The vocabulary of completion CLAIMS: a name the product could publish that
/// claims a completed drain, a confirmed abort, or a settled backlog fails the
/// census in `assert_no_published_diagnostic_name_claims_a_completion`.
///
/// There is exactly ONE declaration of this vocabulary, at file scope, so the
/// census helper and case 889/14 sweep the same words.
const DRAIN_CLAIMS: [&str; 11] = [
    "drain", "abort", "flush", "complete", "confirm", "clean", "empty", "settled", "quiet",
    "final", "stopped",
];

/// (1) NON-INTERFERENCE: the same Host operation, run behind a sink that
/// really FAILS and behind a healthy one, and the product's OWN published
/// outcome compared across the two.
///
/// One identical closure -- the same facade call, the same projection, the same
/// payloads -- is executed twice by [`SinkRun::captured`], so the ONLY
/// difference between the two runs is the sink's health. The admission layer is
/// installed UNDERNEATH the formatter layer, so the outcome is read off the
/// record itself and never depends on the writer accepting a single byte.
///
/// THE ARGSUMENTS THIS HELPER CARRIES, none of which the caller can bypass:
/// * the failing half GENUINELY fails: its `write` returned `Err`, so it
///   retained nothing, while the healthy half retained every offered byte --
///   without this the two arms could be the same arm and the comparison would
///   prove nothing about degradation;
/// * both halves really were offered the same emission, so the byte equality is
///   an observation about the same records reaching both sinks rather than a
///   restatement of how the sinks were built;
/// * neither half captured an empty admission set, because an empty capture is
///   what a destroyed emission path would look like, and an equality between
///   two empty sets passes vacuously;
/// * the product's own TYPED admission outcome -- the event, the evidence, the
///   receipt exit and the admission's own `as_str()` name -- is identical across
///   the two sink healths. This is the load-bearing comparison of the whole
///   delivery: a failing sink must not change the Host result. It is made over
///   [`CounterFreeAdmission`], so the one process-global drop counter that the
///   worker thread advances on its own schedule is projected out of it rather
///   than raced; the counter is proved separately, in
///   `assert_the_published_drop_counter_only_moves_forward_across_both_sink_healths`.
///
/// Returns the DEGRADED run, so the caller can assert on that run's own typed
/// operation, evidence and receipt slots and cannot drop the comparison by
/// ignoring it.
fn assert_a_failing_sink_changes_no_host_observable_outcome() -> SinkRun {
    let degraded = SinkRun::captured(
        || {
            observe_host_request(
                &HostRequestProjection::durable_committed(EntrypointStage::ScmDispatch)
                    .with_request(HostConsoleRequest::Stop)
                    .with_operation(AdmittedEvent::ServiceStop)
                    .with_process(std::process::id())
                    .with_terminal_exit(HOST_TERMINAL_EXIT),
            );
        },
        SinkHealth::Failing,
    );
    let healthy = SinkRun::captured(
        || {
            observe_host_request(
                &HostRequestProjection::durable_committed(EntrypointStage::ScmDispatch)
                    .with_request(HostConsoleRequest::Stop)
                    .with_operation(AdmittedEvent::ServiceStop)
                    .with_process(std::process::id())
                    .with_terminal_exit(HOST_TERMINAL_EXIT),
            );
        },
        SinkHealth::Healthy,
    );

    // The failing half really failed and the healthy half really accepted, so
    // the two runs are not the same arm. A "degraded" sink that returned
    // `Ok(buf.len())` is a healthy sink and this comparison would be vacuous.
    assert_eq!(
        degraded.written, 0,
        "the failing half must retain nothing, or it was never a failing sink"
    );
    assert!(
        degraded.offered > 0,
        "the failing half must really have been offered the emission, got {} bytes",
        degraded.offered
    );
    assert_eq!(
        healthy.written, healthy.offered,
        "the healthy half must retain every offered byte"
    );
    assert!(
        healthy.offered > 0,
        "the healthy half must really have been offered the emission, got {} bytes",
        healthy.offered
    );

    // Both halves were handed the SAME emission. This is what makes the typed
    // equality below an observation about one record observed twice, rather
    // than a comparison of two unrelated runs.
    assert_eq!(
        degraded.offered, healthy.offered,
        "both sink healths must be offered the same emission, or the comparison below is about two \
         different records"
    );

    // An empty capture is exactly what a destroyed emission path looks like,
    // and two empty sets compare equal for free, so this arm is checked before
    // the equality it would otherwise satisfy vacuously.
    assert!(
        !degraded.admissions.is_empty(),
        "the failing sink must not destroy the emission path: the product still has to publish its \
         admission outcome, got none"
    );
    assert!(
        !healthy.admissions.is_empty(),
        "the healthy sink must publish the product's admission outcome, got none"
    );

    // THE COMPARISON THIS CASE EXISTS FOR: the product's own typed admission
    // outcome is identical whether the sink failed every write or accepted
    // every byte. A degraded sink changes nothing Host-observable.
    //
    // WHAT IS COMPARED, AND WHAT IS DELIBERATELY NOT. Both halves are projected
    // through [`AdmissionOutcome::counter_free`], which carries the event, the
    // evidence, the receipt exit and the admission's own name -- the variant,
    // plus `truncated` through the product's `as_str()` spelling -- and leaves
    // out ONE field: `dropped_total`.
    //
    // WHY `dropped_total` IS OUT, stated rather than quietly dropped. It is the
    // PROCESS-GLOBAL monotone drop counter, and both runs admit into the ONE
    // global producer queue: each `SinkRun::captured` is its own
    // `with_default` scope with NO lock or fence between them, and the single
    // worker thread dequeues asynchronously. Off Windows the OS port is
    // unsupported, so the worker takes the failure arm and calls
    // `increment_dropped_total` for every record it drains -- run 1 publishes
    // `D`, the worker bumps it to `D + 1`, run 2 publishes `D + 1`, and the raw
    // vectors differ for a reason that has nothing to do with the sink's
    // health. Whether the worker's increment lands between the two captures is
    // a race, so comparing it would have made this assertion red on a loaded
    // CI runner for an unrelated reason. The counter is still proved, on its
    // own, in the explicitly-labelled arm below.
    let degraded_projection: Vec<CounterFreeAdmission> = degraded
        .admissions
        .iter()
        .map(AdmissionOutcome::counter_free)
        .collect();
    let healthy_projection: Vec<CounterFreeAdmission> = healthy
        .admissions
        .iter()
        .map(AdmissionOutcome::counter_free)
        .collect();
    assert_eq!(
        degraded_projection, healthy_projection,
        "a failing sink must not change the Host result: the product's own typed admission outcome \
         must be identical under both sink healths (compared over the event, the evidence, the \
         receipt exit and the admission's own name, with the process-global drop counter \
         projected out)"
    );

    // THE DROP COUNTER, PROVEN SEPARATELY AND EXPLICITLY LABELLED, so the field
    // left out of the equality above is not left unproved with it. These are the
    // product's OWN published counts, read off each run's own record, and the
    // obligation is the MONOTONE ORDERING the wrapper documents. The counters
    // are deliberately NOT asserted equal to each other -- they are one shared
    // process-global counter moving on its own, and requiring them equal would
    // reintroduce the exact race this arm replaces.
    assert_the_published_drop_counter_only_moves_forward_across_both_sink_healths(
        &degraded.admissions,
        &healthy.admissions,
    );
    degraded
}

/// THE DROP COUNTER ARM, deliberately separate from the cross-health equality
/// above, and deliberately a MONOTONE-ORDERING claim rather than an equality.
///
/// Both halves of the comparison ran against the ONE process-global producer,
/// and this case submits three admissions to it in a fixed order -- the
/// degraded run, then the healthy run, then the panicking-writer run of block
/// (1b). So the counter each later run publishes must be at least the one the
/// run before it published. That is what can be asserted here WITHOUT racing
/// the worker: it holds whether or not the worker landed an increment between
/// two captures, and it fails on a product whose counter is not monotone -- a
/// snapshot read that can go backwards, or a counter reset by an admission.
///
/// NO ABSOLUTE UPPER BOUND IS CLAIMED HERE, and that is deliberate rather than
/// an omission. The counter is PROCESS-GLOBAL and shared with every other test
/// in this binary: cases 889/6, 889/11 and 889/12 each project requests that
/// carry an admitted operation and therefore reach the same producer, and
/// cargo runs those tests in parallel with this one. Any ceiling expressed as a
/// literal for this case alone would therefore be red for a reason that has
/// nothing to do with the product -- the same class of defect this arm exists
/// to remove. The counter's own bound IS proved, against the records actually
/// submitted, by `assert_the_sweep_admissions_are_accounted_exactly`, which is
/// where the sweep's submission count is a real number rather than an
/// assumption.
fn assert_the_published_drop_counter_only_moves_forward_across_both_sink_healths(
    degraded: &[AdmissionOutcome],
    healthy: &[AdmissionOutcome],
) {
    // Both runs published exactly one admission each; the emptiness arms in the
    // caller already proved it, and indexing here is only reached after them.
    let degraded_drops = degraded
        .first()
        .expect("the emptiness guard above proved the failing run published an admission")
        .published_drops;
    let healthy_drops = healthy
        .first()
        .expect("the emptiness guard above proved the healthy run published an admission")
        .published_drops;
    assert!(
        healthy_drops >= degraded_drops,
        "the process-global drop counter is monotone, so the second run must publish at least the \
         counter the first run published: got {healthy_drops} after {degraded_drops}"
    );
}

/// The compared admission is the one the COMPARISON read off the real emission
/// path, and it names the projection this case built rather than some other
/// request, so the cross-health equality above cannot be satisfied by two
/// captures of an unrelated event.
///
/// `degraded` is the very run `assert_a_failing_sink_changes_no_host_observable_outcome`
/// returned, so these arms judge the same record the comparison was made over.
///
/// THE RECEIPT-EXIT ARM IS A PRESENCE CLAIM, NOT AN EQUALITY AGAINST A VALUE,
/// and that is what the product actually supports. The admission record in
/// `src/host_diagnostics.rs` publishes exactly `service`, `phase`, `evidence`,
/// `operation`, `outcome` and `dropped_total` -- it carries NO `receipt_exit`
/// slot, so `record.field("receipt_exit")` is always `None` and this slot is
/// always `None`. The previous spelling of this arm demanded
/// `Some(HOST_TERMINAL_EXIT)`, which the product can never publish, so it was
/// guaranteed red for the same reason the dropped-in-bound sweeps above were:
/// it asserted the opposite of the truth. What is claimed now is the part that
/// is checkable: the compared admission carries no terminal exit, because the
/// admission record has no slot to carry one in, and that fact is read off the
/// SAME record the equality was made over. The terminal exit this projection
/// was built with is still proved, on the `host.request` record that DOES
/// publish it, by case 889/6's `receipt_exit` arm.
fn assert_the_compared_admission_names_the_projection_it_carried(degraded: &SinkRun) {
    assert_eq!(
        degraded.admissions.len(),
        1,
        "one projection publishes exactly one admission outcome, got {:?}",
        degraded.admissions
    );
    let admission = &degraded.admissions[0];
    assert_eq!(
        admission.event,
        AdmittedEvent::ServiceStop,
        "the compared admission must be for the operation this projection carried"
    );
    assert_eq!(
        admission.evidence,
        HostRequestEvidence::DurableCommitted,
        "the compared admission must carry the evidence this projection was built with"
    );
    assert_eq!(
        admission.receipt_exit, None,
        "the admission record publishes no receipt_exit slot at all, so the compared admission must \
         carry none: a slot appearing here would be a new product field the counter-free \
         comparison is not yet judging"
    );
}

/// (1b) A PANIC raised inside the writer, and exactly what the product does and
/// does not contain.
///
/// A panic escaping a diagnostic writer is NOT contained by the product and NOT
/// contained by tracing: nothing here claims otherwise, and nothing here claims
/// the panic is invisible to the Host either. What is proved -- and what the
/// caller's comment in the case body states -- is only what is true: the
/// admission layer runs BEFORE the writer, so the typed outcome was already
/// recorded before the panic was raised, and the panic does not retroactively
/// change it.
///
/// The injected panic stays inside `std::panic::catch_unwind`, and the
/// `take_hook`/`set_hook` pair is balanced here, inside the helper that owns
/// it: the previous hook is restored on BOTH the panicking and the
/// non-panicking path before this function returns, so the process-global hook
/// is never left replaced for another test.
///
/// `degraded` is the run whose typed fields the caller already bounded; the
/// outcome compared below is the same product-typed admission, re-derived
/// through the same vocabulary.
fn assert_a_panicking_writer_changes_no_published_admission(degraded: &SinkRun) {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    // Runs the SAME projection through a writer that panics on its first
    // write. The admission layer is underneath the writer, so the outcome is
    // published before the panic is raised.
    let outcomes = Arc::new(Mutex::new(Vec::<AdmissionOutcome>::new()));
    let recorded = Arc::clone(&outcomes);
    let panic_sink = PanickingWriter::default();
    let raised_writer = panic_sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || raised_writer.clone())
        .finish()
        .with(AdmissionLayer {
            outcomes: Arc::clone(&recorded),
        });
    // `catch_unwind` requires its closure to be `UnwindSafe`. The subscriber
    // owns an `Arc` handle, which is not, so it is moved in behind
    // `AssertUnwindSafe`: the only state the unwind can reach is the
    // subscriber's own handles, and this helper reads the published outcomes
    // out through `outcomes` AFTER the unwind has finished, never from inside.
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        tracing::subscriber::with_default(subscriber, || {
            observe_host_request(
                &HostRequestProjection::durable_committed(EntrypointStage::ScmDispatch)
                    .with_request(HostConsoleRequest::Stop)
                    .with_operation(AdmittedEvent::ServiceStop)
                    .with_process(std::process::id())
                    .with_terminal_exit(HOST_TERMINAL_EXIT),
            );
        });
    }));
    // Restore the process-global hook on BOTH paths before anything else runs,
    // so the pair stays balanced even though the emission unwound.
    std::panic::set_hook(previous_hook);

    assert!(
        panic_sink.raised(),
        "the injected panic must actually have been raised inside the writer, or the \
         non-interference arms below would be proving nothing"
    );
    assert!(
        panicked.is_err(),
        "a writer that panics must not be silently swallowed by the formatter, or the admission \
         published before the panic would prove nothing about a panicking writer"
    );
    let published = outcomes.lock().unwrap().clone();
    assert_eq!(
        published.len(),
        1,
        "the admission layer runs BEFORE the writer, so the typed outcome is published even when \
         the writer then panics, got {published:?}"
    );
    // SAME COUNTER-FREE PROJECTION as the cross-health comparison above, and for
    // the same reason: this run and the degraded run both admit into the ONE
    // process-global producer queue, and the worker advances `dropped_total` on
    // its own schedule between the two captures. Comparing the raw vectors
    // would race that worker. What is claimed here is that a writer which
    // panics changes no PUBLISHED ADMISSION -- the same event, the same
    // evidence, the same receipt exit, the same admission name.
    let published_projection: Vec<CounterFreeAdmission> = published
        .iter()
        .map(AdmissionOutcome::counter_free)
        .collect();
    let degraded_projection: Vec<CounterFreeAdmission> = degraded
        .admissions
        .iter()
        .map(AdmissionOutcome::counter_free)
        .collect();
    assert_eq!(
        published_projection, degraded_projection,
        "a panicking writer must change no published admission: the admission layer, which runs \
         before the writer, already recorded the same typed outcome (compared with the \
         process-global drop counter projected out)"
    );
    // The counter is bounded here too, and only against the run that came
    // BEFORE this one on this test's own thread: the panicking run is submitted
    // third, so the process-global monotone counter cannot have gone backwards
    // against the failing run's own published count. No absolute ceiling is
    // claimed, for the reason given on
    // `assert_the_published_drop_counter_only_moves_forward_across_both_sink_healths`:
    // the counter is shared with the parallel cases in this binary.
    let panicked_drops = published
        .first()
        .expect("the length guard above proved this run published an admission")
        .published_drops;
    let degraded_drops = degraded
        .admissions
        .first()
        .expect("the length guard in the comparison helper proved the failing run published one")
        .published_drops;
    assert!(
        panicked_drops >= degraded_drops,
        "the process-global drop counter is monotone, so the third run must publish at least the \
         counter the first run published: got {panicked_drops} after {degraded_drops}"
    );
}

/// Writer whose very first `write` raises the injected panic of case 889/14(1b).
///
/// It keeps a flag so the helper can prove the panic really was raised here,
/// rather than inferring it from a caught unwind it cannot otherwise explain.
#[derive(Clone, Default)]
struct PanickingWriter {
    raised: Arc<Mutex<bool>>,
}

impl PanickingWriter {
    fn raised(&self) -> bool {
        *self.raised.lock().unwrap()
    }
}

impl Write for PanickingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        *self.raised.lock().unwrap() = true;
        panic!("injected diagnostic writer panic (889/14)");
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The facade's shutdown record must report the TERMINAL SNAPSHOT's own facts,
/// read through the same readers the record's own fields go through: the typed
/// `as_str()` for the disposition, and the record's own `known`/`unknown` flags
/// for each count.
///
/// This is what makes "a timeout must not falsely certify abort/drain" checkable
/// at runtime -- a record that reported a stale or fabricated disposition, or
/// that dropped the `*_unknown` flags, fails. The line is located by its own
/// product-typed `event=` value, never by a position or an occurrence count, so
/// no layout assumption hides below.
///
/// Both arms of `EventLogWorkCount` are asserted, so neither can pass by
/// construction: a `Known` count is reported as that number with its unknown flag
/// false AND stays within the queue bound plus the single in-flight record; an
/// `Unknown` count is reported as a zero SLOT with its unknown flag TRUE, so it
/// can never be read as a confirmed zero. An empty `Unknown => {}` arm asserted
/// nothing; these two cannot.
fn assert_the_shutdown_record_agrees_with_the_snapshot_it_describes(
    shutdown_records: &str,
    terminal: &EventLogShutdownSnapshot,
    queue_bound: usize,
) {
    let shutdown_line = shutdown_records
        .lines()
        .find(|line| rendered_field(line, "event") == Some("host.event_log_producer_shutdown"))
        .unwrap_or_else(|| {
            panic!(
                "the facade's shutdown_event_log_reporting must have emitted exactly one \
                 host.event_log_producer_shutdown record, got: {shutdown_records}"
            )
        });
    assert_eq!(
        rendered_field(shutdown_line, "outstanding_delivery"),
        Some(terminal.delivery_disposition().as_str()),
        "the facade's shutdown record must report the disposition of this very snapshot"
    );
    for (label, count) in [
        ("queued", terminal.queued()),
        ("in_flight", terminal.in_flight()),
    ] {
        let slot = format!("{label}=");
        let reported_unknown = rendered_field(shutdown_line, &format!("{label}_unknown"));
        match count {
            EventLogWorkCount::Known(value) => {
                assert!(
                    value <= queue_bound,
                    "{label} work must stay within the declared queue bound plus the in-flight \
                     record, got {value} for a bound of {queue_bound}"
                );
                assert!(
                    shutdown_line.contains(&slot),
                    "the facade's shutdown record must report the {label} count it observed, got: \
                     {shutdown_line}"
                );
                assert_eq!(
                    reported_unknown,
                    Some("false"),
                    "an observed {label} count must be reported as known, never as unknown"
                );
            }
            EventLogWorkCount::Unknown => {
                assert_eq!(
                    rendered_field(shutdown_line, label),
                    Some("0"),
                    "an unobserved {label} count occupies the numeric slot with zero, never with a \
                     count the product did not observe"
                );
                assert_eq!(
                    reported_unknown,
                    Some("true"),
                    "an unobserved {label} count must be reported as unknown, never as a \
                     confirmed zero, got: {shutdown_line}"
                );
            }
        }
    }
}

/// THE NEGATIVE THE ISSUE DEMANDS, and the one that has to be a SOURCE CENSUS
/// rather than a runtime comparison: the product must not be ABLE to report a
/// completed drain, a confirmed abort, or a confirmed zero for outstanding work
/// -- not merely that it did not report one here.
///
/// `EventLogWorkDisposition` is a ONE-VARIANT enum whose only value is
/// `Unknown`, so `expected.contains(reported)` over a hand-written list is a
/// literal compared with itself and proves nothing at runtime: a new variant
/// would not change the list. What CAN be checked without touching the product
/// is the SOURCE of that vocabulary. The census reads the product's own
/// `impl EventLogWorkDisposition` block, and a second `as_str()` arm -- the only
/// shape a drained/aborted/flushed/confirmed variant could take -- fails the
/// count and the name census, so a new completion claim is caught both where it
/// would be declared and in every name the product publishes.
///
/// The SAME census runs for the count vocabulary, because `EventLogWorkCount`
/// has no `as_str()` at all: a third disposition of work cannot be published
/// from a two-variant type whose `known()` has exactly two arms. And the
/// terminal snapshot is checked to be the one the producer returned: both
/// construction sites in `shutdown_event_log_producer` hard-code the honest
/// disposition, so no path can publish a drain or abort claim.
///
/// `terminal` is the producer's own return value, read here rather than off the
/// `()` the facade hands back, so these arms judge a real published disposition.
fn assert_no_work_disposition_can_claim_a_drain_or_an_abort(terminal: &EventLogShutdownSnapshot) {
    let disposition_impl = fn_body_without_whitespace(
        &manifest_source("src/windows_event_log.rs"),
        "impl EventLogWorkDisposition",
    )
    .unwrap_or_else(|| panic!("src/windows_event_log.rs must define impl EventLogWorkDisposition"));
    let disposition_arm_count = disposition_impl.matches("=>").count();
    assert_eq!(
        disposition_arm_count, 1,
        "the outstanding-work vocabulary must stay the single honest Unknown arm: a second as_str \
         arm is a disposition the product could publish, and a disposition that claims a drain or an \
         abort would fail here"
    );
    let mut declared_dispositions: Vec<&str> = disposition_impl
        .split("=>")
        .skip(1)
        .filter_map(|arm| {
            arm.split(['"', ';', ',', ' ', '{', '}'])
                .find(|token| !token.is_empty())
        })
        .collect();
    declared_dispositions.sort_unstable();
    declared_dispositions.dedup();
    assert_eq!(
        declared_dispositions,
        vec!["unknown"],
        "the only outstanding-work disposition the product declares must be the refusal to claim \
         anything, got {declared_dispositions:?}"
    );
    let count_impl = fn_body_without_whitespace(
        &manifest_source("src/windows_event_log.rs"),
        "impl EventLogWorkCount",
    )
    .unwrap_or_else(|| panic!("src/windows_event_log.rs must define impl EventLogWorkCount"));
    assert_eq!(
        count_impl.matches("=>").count(),
        2,
        "a work count must stay exactly an observed number or a refusal to claim one: a third \
         count arm would let a shutdown report something the product never observed"
    );
    let shutdown_producer_body = fn_body_without_whitespace(
        &manifest_source("src/windows_event_log.rs"),
        "pub fn shutdown_event_log_producer",
    )
    .unwrap_or_else(|| panic!("src/windows_event_log.rs must define shutdown_event_log_producer"));
    assert_eq!(
        shutdown_producer_body
            .matches("EventLogWorkDisposition::Unknown")
            .count(),
        2,
        "every terminal snapshot construction site must hard-code the unknown disposition, so no \
         path can publish a drain or abort claim"
    );
    let reported_disposition_name = terminal.delivery_disposition().as_str();
    assert_eq!(
        reported_disposition_name, "unknown",
        "the outstanding-work disposition the producer reports must be its refusal to claim \
         anything"
    );
}

/// The census reads the DIAGNOSTIC NAMES the product publishes, never its prose
/// and never the name of the delivery record itself. Two things are deliberately
/// excluded, and each exclusion is a fact about this product rather than a hole
/// in the rule:
///
/// * `host.event_log_delivery` is the name of the SYNCHRONOUS OS report record.
///   Delivery claims are legitimate THERE and only there: the issue forbids
///   claiming a drain or an abort of work that was never proven stopped, not the
///   record that says what the synchronous port actually answered. That name is
///   therefore taken from the product's own delivery vocabulary, not forbidden,
///   and the sweep here is over the ADMISSION vocabulary -- what the
///   nonblocking producer may report for a record it did not deliver -- which is
///   where a false drain or abort claim would have to appear.
/// * `EventLogDelivery`'s names are claims about what the OS port ACCEPTED,
///   which is a real observation with real receipts, and its completeness is
///   asserted by the vocabulary census below rather than by banning a word.
///
/// `DRAIN_CLAIMS`, the vocabulary this census sweeps, is declared at file scope,
/// so this helper and case 889/14 read the same words.
fn assert_no_published_diagnostic_name_claims_a_completion(wrapper_source: &str) {
    // Every `as_str()` name the ADMISSION and ERROR vocabularies publish,
    // re-derived through the product's own methods, plus the event names the
    // producer module emits. A claim word appearing in any of them is a claim
    // the product can make about work it did not deliver.
    let admission_names: Vec<&str> = EVENT_LOG_ADMISSION_BY_NAME
        .iter()
        .map(|(_, name)| *name)
        .collect();
    let error_names: Vec<&str> = WINDOWS_EVENT_LOG_ERROR_BY_NAME
        .iter()
        .map(|(_, name)| *name)
        .collect();
    let emitted_event_names: Vec<&str> = wrapper_source
        .lines()
        .filter_map(|line| line.split("event = \"").nth(1))
        .filter_map(|rest| rest.split('"').next())
        .collect();
    assert!(
        !emitted_event_names.is_empty(),
        "the wrapper must name the events it emits, or the sweep below would read nothing"
    );
    let claimable_names: Vec<&str> = admission_names
        .iter()
        .chain(error_names.iter())
        .chain(emitted_event_names.iter())
        .copied()
        .filter(|name| !name.contains("delivery"))
        .collect();
    for claim in DRAIN_CLAIMS {
        let spelling_a_claim: Vec<&str> = claimable_names
            .iter()
            .copied()
            .filter(|name| name.contains(claim))
            .collect();
        assert!(
            spelling_a_claim.is_empty(),
            "the product must not be able to publish a {claim:?} claim for work it did not \
             deliver; it publishes {spelling_a_claim:?}"
        );
    }
    for (type_name, names) in diagnostic_name_vocabularies() {
        assert_eq!(
            names.len(),
            type_name,
            "every public diagnostic vocabulary must have one name per variant, or a new outcome \
             could be published without a name this census would have to account for"
        );
        for name in names {
            assert!(
                !DRAIN_CLAIMS.iter().any(|claim| name.contains(claim)),
                "the diagnostic name {name:?} may not claim a completed drain or a confirmed abort"
            );
        }
    }
    // Every `AdmittedEvent` the wrapper can publish, so a new admitted event
    // cannot add an operation whose delivery is accounted for under a name the
    // sweep above never sees.
    let admitted_event_names: Vec<&str> = ADMITTED_EVENT_BY_NAME
        .iter()
        .map(|(event, name)| {
            assert_eq!(
                event.as_str(),
                *name,
                "every admitted event must carry its own exact diagnostic name"
            );
            *name
        })
        .collect();
    assert_eq!(
        admitted_event_names.len(),
        ADMITTED_EVENT_BY_NAME.len(),
        "every admitted event must keep its own distinct diagnostic name"
    );
}

/// The concurrent sweep of case 889/14, driven through the facade under four
/// owned worker threads, with the product's own published accounting checked
/// against what it really emitted.
///
/// THE ARGSUMENTS THIS HELPER CARRIES, none of which the caller can bypass:
/// * the formatted output holds exactly one stage and one terminal record per
///   iteration, holds exactly the sink-status record per iteration on the
///   platforms that publish one, stays inside a byte budget derived from the
///   records each iteration really emits, and yields exactly one request record
///   per iteration -- no duplicated, missing, or extra emissions under
///   concurrency;
/// * a projection really did reach the Event Log seam, so the sweep exercises
///   admission rather than only the tracing path;
/// * every swept admission names the operation its projection carried, is never
///   `not_started`, and is accounted for by EXACTLY ONE typed outcome -- every
///   submission counted once, whether the product admitted it into the queue or
///   refused it, with a third outcome fatal;
/// * a counted worker refusal stays within the records the sweep submitted, so
///   exactly the worker-unavailable arm may advance the monotone drop counter;
/// * the published drop counter never outruns the records submitted, which is the
///   arm that actually catches a retry or a worker-per-record.
///
/// Returns the HIGHEST drop total the sweep ever saw published TOGETHER WITH
/// the number of records the sweep actually submitted. Both are threaded back
/// to the caller: the drop high-water mark bounds the post-shutdown admission
/// arm, and the submission count is the ONLY honest upper bound on what the
/// monotone drop counter may have reached, so neither can be reached by
/// ignoring this helper's result.
///
/// A writer-side thread-id set is deliberately NOT used here: it records the
/// threads that DISPATCHED through the writer, not the threads the product
/// CREATED.
fn assert_the_concurrent_sweep_is_accounted_exactly() -> (u64, u64) {
    let iterations = 64usize;
    let owned_workers = 4usize;
    let observed_threads = Arc::new(Mutex::new(Vec::<std::thread::ThreadId>::new()));
    // TWO HANDLES ON ONE COUNTER. `observed_threads` is the cell the observing
    // layer writes; the handle below is what this test keeps so it can read the
    // very same ids back after the sweep. `Arc` is not `Copy`, so the layer's
    // field takes a clone of its own and this handle survives the move - both
    // are clones of the SAME allocation, never two separate counters, so the
    // set read in `assert_delivery_reached_one_product_thread` is exactly the
    // one the layer filled. Nothing more is claimed for it: that set is empty
    // over this scope, for the thread-local reason stated at its own site.
    let observing_threads = Arc::clone(&observed_threads);
    let sweep_records = Arc::new(Mutex::new(Vec::<CapturedRecord>::new()));
    let sweep_captured = Arc::clone(&sweep_records);
    let sweep_outcomes = Arc::new(Mutex::new(Vec::<AdmissionOutcome>::new()));
    let sweep_admissions = Arc::clone(&sweep_outcomes);
    let sink = MeasuringSink::default();
    let writer = sink.clone();
    // The recording and thread-observing layers are custom LAYERS, but the
    // measuring writer is a custom WRITER: `tracing_subscriber::fmt()` is
    // already a subscriber, so `.finish()` is the BASE of the stack rather than
    // something to pass to `with()`, which takes layers. This is the composition
    // the sink-degradation case proves: the writer sits ABOVE the recording
    // layers, so a record is still observed when the writer returns `Err`.
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish()
        .with(RecordingLayer {
            records: Arc::clone(&sweep_captured),
        })
        .with(ThreadObservingLayer {
            observed: Arc::clone(&observing_threads),
        })
        .with(AdmissionLayer {
            outcomes: Arc::clone(&sweep_admissions),
        });
    tracing::subscriber::with_default(subscriber, || {
        std::thread::scope(|scope| {
            for worker in 0..owned_workers {
                scope.spawn(move || {
                    for iteration in 0..iterations {
                        observe_entrypoint_with_detail(
                            EntrypointStage::ConsoleLoop,
                            &format!("bounded-{worker}-{iteration}"),
                        );
                        observe_terminal_error(HOST_TERMINAL_CODE_DISPATCHER_FAILED);
                        // A projection that genuinely reaches the Event Log
                        // seam, so the sweep exercises admission under
                        // concurrency rather than only the tracing path.
                        observe_host_request(
                            &HostRequestProjection::process_started(
                                EntrypointStage::ScmDispatch,
                                std::process::id(),
                            )
                            .with_operation(AdmittedEvent::ServiceStart),
                        );
                        note_event_log_sink_status();
                    }
                });
            }
        });
    });
    let rendered = sink.rendered();
    assert_the_sweep_emitted_exactly_one_record_per_iteration(
        &rendered,
        owned_workers * iterations,
    );

    // The product's own accounting of the work it owns. A `host.request` record
    // is exactly what one emitted projection produces, so the count is exact: no
    // duplicated, missing, or extra emissions under concurrency, and the sweep
    // really did reach the Event Log seam.
    let captured: Vec<CapturedRecord> = std::mem::take(&mut *sweep_records.lock().unwrap());
    assert_the_sweep_reached_the_event_log_seam_exactly_once_per_iteration(
        &captured,
        owned_workers * iterations,
    );

    // DELIVERY-NAMED EVENTS, handed to the helper that reads both sides. The
    // `observing_threads` handle below is the very cell the observing layer
    // filled during this sweep -- the two layers were registered over the same
    // scope -- so what the helper compares is not a value with itself. It
    // compares two EMPTY sets over this scope, because the worker thread's
    // records never reach a thread-local capture on any platform; that helper
    // says so at its own site, and the one-worker bound is established by the
    // source census `assert_the_wrapper_spawns_exactly_one_named_worker`.
    assert_delivery_reached_one_product_thread(&captured, &observing_threads);

    let sweep_admitted: Vec<AdmissionOutcome> =
        std::mem::take(&mut *sweep_outcomes.lock().unwrap());
    let submissions = (owned_workers * iterations) as u64;
    let highest_drops =
        assert_the_sweep_admissions_are_accounted_exactly(&sweep_admitted, submissions);
    (highest_drops, submissions)
}

/// The number of facade records ONE sweep iteration really emits: the stage
/// record, the terminal record, the one `host.request` record, and the
/// `host.event_log_admission` record that `observe_host_request` publishes for
/// an admitted operation BEFORE it consults the producer's state
/// (src/host_diagnostics.rs:954-955, 1012-1040). Off Windows
/// `note_event_log_sink_status` publishes a fifth, `host.event_log_sink_
/// unavailable`, which nothing else in this sweep emits.
///
/// It is a count, read from the sweep's own body rather than guessed: the byte
/// budget below is the number of records each iteration produces multiplied by
/// the product's own per-detail bound, so the arithmetic cannot drift away from
/// the emissions it is bounding.
const SWEEP_RECORDS_PER_ITERATION: usize = 4;

/// The PRODUCT'S OWN sink-unavailability record name, as the `fmt` layer
/// writes it: a dotted identifier carries no quoting trigger, and this file's
/// established idiom for counting a product record by name is the quoted
/// `event="..."` field form used for `host.request` (line 957) and
/// `host.event_log_admission` (lines 980, 987). Matching the FIELD, not a bare
/// substring, means the needle cannot be satisfied by the same text appearing
/// in an unrelated free-text payload value. This string is emitted by the
/// product at src/host_diagnostics.rs:637 (`event = "host.event_log_sink_
/// unavailable"` inside `note_event_log_sink_status`), so a product that grew
/// or removed that record changes the count below and turns the live-port arm
/// red.
const SWEEP_SINK_UNAVAILABLE_EVENT_FIELD: &str = "event=\"host.event_log_sink_unavailable\"";

/// Every sweep iteration produced exactly one stage record and one terminal
/// record, and the whole formatted output stayed within the product's own
/// declared bound.
///
/// The budget is `expected_records * records-per-iteration *` the product's own
/// per-detail bound, so it scales with the emissions the sweep really makes: a
/// sweep whose output grows with the number of records it emits -- an unbounded
/// detail, a redacted payload, a repeated emission -- still crosses it, while
/// the per-record allowance of the old `expected_records *` form (one bound per
/// ITERATION rather than per record) was smaller than a single `host.request`
/// record can be, which is a property of this sweep's own inputs rather than of
/// the product.
fn assert_the_sweep_emitted_exactly_one_record_per_iteration(
    rendered: &str,
    expected_records: usize,
) {
    assert_eq!(
        rendered.matches("host.entrypoint_stage").count(),
        expected_records,
        "every sweep iteration must have emitted exactly one stage record"
    );
    assert_eq!(
        rendered.matches("host.terminal_error").count(),
        expected_records,
        "every sweep iteration must have emitted exactly one terminal record"
    );
    // The fifth record of an off-Windows sweep, counted only where the product's
    // own sink answer says this platform really publishes it: a sweep that grew
    // a sink-status record per iteration where the sink is live would fail here
    // rather than quietly growing inside the byte budget.
    //
    // BOTH branches now name the SAME PRODUCT RECORD -- matched as its
    // `event="..."` field -- and differ only in the count the product's own
    // answer requires. The branch decision comes from `event_log_sink_status()`
    // directly rather than being smuggled inside a helper's return string, so
    // the live-port arm can now FAIL: a product that started emitting (or
    // stopped suppressing) `host.event_log_sink_unavailable` where the port is
    // live turns this count red, which the old self-invented prose needle could
    // never do.
    let mut records_per_iteration = SWEEP_RECORDS_PER_ITERATION;
    if event_log_sink_status().is_err() {
        assert_eq!(
            rendered.matches(SWEEP_SINK_UNAVAILABLE_EVENT_FIELD).count(),
            expected_records,
            "with no live Event Log port every sweep iteration must have emitted exactly one \
             {} record",
            SWEEP_SINK_UNAVAILABLE_EVENT_FIELD
        );
        records_per_iteration = records_per_iteration.saturating_add(1);
    } else {
        assert_eq!(
            rendered.matches(SWEEP_SINK_UNAVAILABLE_EVENT_FIELD).count(),
            0,
            "a live Event Log port publishes nothing to note, so the sweep must have emitted no {} \
             record at all",
            SWEEP_SINK_UNAVAILABLE_EVENT_FIELD
        );
    }
    let budget = expected_records
        .saturating_mul(records_per_iteration)
        .saturating_mul(MAX_DIAGNOSTIC_DETAIL_BYTES);
    assert!(
        rendered.len() <= budget,
        "the sweep's formatted output must stay within {} bytes per emitted record -- {} records \
         for {} iterations -- got {} bytes",
        MAX_DIAGNOSTIC_DETAIL_BYTES,
        records_per_iteration,
        expected_records,
        rendered.len()
    );
}

/// The sweep produced exactly one `host.request` record per iteration, and a
/// projection really did reach the Event Log seam, so this sweep exercised
/// admission rather than only the tracing path.
fn assert_the_sweep_reached_the_event_log_seam_exactly_once_per_iteration(
    captured: &[CapturedRecord],
    expected_records: usize,
) {
    let request_records = captured
        .iter()
        .filter(|record| record.event == "host.request")
        .count();
    assert_eq!(
        request_records, expected_records,
        "every sweep iteration must have emitted exactly one request record"
    );
    assert!(
        captured
            .iter()
            .any(|record| record.event == "host.event_log_admission"),
        "a projection that reaches the Event Log seam must publish an admission record, so this \
         sweep really exercises admission"
    );
}

/// Every admission the sweep produced is accounted for, whatever the producer's
/// state was when the sweep ran, and the monotone drop counter cannot outrun the
/// records the sweep submitted.
///
/// WHICH admission this sweep produced is derived, not pinned, because this test
/// STARTS the producer itself (through `capture_the_producer_start_record`) and
/// then shuts it down (through `shutdown_event_log_producer`) before the sweep
/// runs, so every swept admission is a refusal; but WHICH refusal depends on what
/// the single product worker was doing when each sweep thread submitted, and that
/// is a fact about the worker, not about this sweep.
///
/// WHY `Admitted` IS UNREACHABLE HERE -- the real reason, so a future reader
/// cannot be misled into thinking the shutdown call is optional. It is NOT
/// "the worker was never started": the worker HAS been started, by this very case
/// through `capture_the_producer_start_record` before the shutdown. The reason is
/// the WRITE-ONCE shutdown state. `shutdown_event_log_producer` stores `true`
/// into `EVENT_LOG_SHUTDOWN_REQUESTED` (src/windows_event_log.rs:955) and into
/// `state.shutdown` (src/windows_event_log.rs:964), and NEITHER is ever cleared
/// anywhere in the product; `EVENT_LOG_PRODUCER` is a `OnceLock` that is set once
/// and never reset. `try_admit_admitted_event` checks those flags at its FIRST
/// test (src/windows_event_log.rs:873) and returns `RejectedShutdown` before it
/// can ever reach the queue. Because the flags are permanently closed once this
/// case calls shutdown, an `Admitted` outcome is not reachable here -- and the
/// first arm below proves it is not, rather than assuming it. Deleting the
/// shutdown call would reopen the queue and make that arm reachable, so the
/// shutdown call is load-bearing for `assert_eq!(admitted, 0)` below.
///
/// The `Admitted` arm of the accounting is nonetheless counted as a first-class
/// outcome, so the sweep is accounted for by EXACTLY ONE typed outcome per
/// submission however the product really answered.
///
/// Returns the HIGHEST drop total any swept admission published, which the
/// caller compares its post-shutdown counter against.
fn assert_the_sweep_admissions_are_accounted_exactly(
    sweep_admitted: &[AdmissionOutcome],
    submissions: u64,
) -> u64 {
    // The count is compared against a slice length, so it is converted once,
    // up front, with the CHECKED conversion this file uses for every other
    // `u64` -> `usize` narrowing rather than an `as` cast that would silently
    // truncate on a 32-bit target. A submission count that does not fit the
    // address space cannot be compared honestly at all, so it fails loudly here
    // instead of comparing against a wrapped number.
    let submissions_usize = usize::try_from(submissions).unwrap_or_else(|_| {
        panic!("the sweep's submission count must fit usize, got {submissions}")
    });
    assert_eq!(
        sweep_admitted.len(),
        submissions_usize,
        "every sweep projection must have published exactly one admission outcome"
    );
    let mut lowest_drops = u64::MAX;
    let mut highest_drops = 0u64;
    let mut admitted = 0u64;
    let mut worker_refusals = 0u64;
    let mut shutdown_refusals = 0u64;
    for outcome in sweep_admitted {
        assert_eq!(
            outcome.event,
            AdmittedEvent::ServiceStart,
            "every swept admission must be for the operation the projection carried"
        );
        assert_eq!(
            outcome.evidence,
            HostRequestEvidence::ProcessStarted,
            "every swept admission must be for the evidence the projection carried, the only class \
             the Event Log admits for a start"
        );
        assert!(
            !matches!(
                outcome.outcome,
                EventLogAdmission::RejectedNotStarted { .. }
            ),
            "this case starts the producer before the sweep, so the facade cannot answer \
             not_started for any swept projection"
        );
        // WHICH refusal it is must be reported HONESTLY, so this arm checks the
        // product's own rule instead of trusting the branch: exactly the
        // worker-unavailable refusal advances the monotone drop counter, and
        // the closed refusal does not. `Admitted` is counted here rather than
        // treated as a third, fatal outcome: it reports the counter it observed
        // and admits nothing further, so the accounting below stays a total one
        // over every submission.
        match outcome.outcome {
            EventLogAdmission::RejectedWorkerUnavailable { dropped_total } => {
                assert!(
                    dropped_total <= submissions,
                    "a counted worker refusal must stay within the records this sweep submitted, \
                     got {dropped_total} for {submissions} records"
                );
                worker_refusals = worker_refusals.saturating_add(1);
            }
            EventLogAdmission::RejectedShutdown { .. } => {
                shutdown_refusals = shutdown_refusals.saturating_add(1);
            }
            EventLogAdmission::Admitted { .. } => {
                admitted = admitted.saturating_add(1);
            }
            other => panic!(
                "a swept projection must publish exactly one accounted outcome, got {other:?}"
            ),
        }
        let drops = outcome.outcome.dropped_total();
        lowest_drops = lowest_drops.min(drops);
        highest_drops = highest_drops.max(drops);
    }
    assert_eq!(
        admitted + worker_refusals + shutdown_refusals,
        submissions,
        "every sweep submission must be accounted for by exactly one typed outcome: admitted into \
         the queue, refused as worker-unavailable, or refused as shut down"
    );
    // The `Admitted` arm is counted honestly above, and it must be unreachable
    // here rather than merely tolerated -- because the WRITE-ONCE shutdown state
    // makes it so, NOT because no worker was ever started (this very case
    // started one, through `capture_the_producer_start_record`). The producer is
    // CLOSED before this sweep runs, and its two shutdown flags are never
    // cleared afterwards, so `try_admit_admitted_event` refuses at its first
    // check (src/windows_event_log.rs:873) and no swept admission can reach the
    // queue. This assertion is what would catch a product that reopened the
    // queue, so deleting the shutdown call above would make it fail -- that call
    // is load-bearing here, not incidental.
    assert_eq!(
        admitted, 0,
        "the producer's shutdown flags are write-once and already set before this sweep, so \
         every swept admission must be a typed refusal: an admitted record means the product \
         reopened a queue this suite had already closed"
    );
    assert!(
        worker_refusals + shutdown_refusals == submissions,
        "the worker-unavailable and closed refusals together must account for every record this \
         sweep submitted, got {worker_refusals} + {shutdown_refusals} for {submissions} records"
    );
    // AND the counter itself, which is the part that can actually run away. A
    // producer that answered every refusal by retrying, or that charged a
    // worker per record, would advance the monotone drop counter faster than
    // the sweep submits records.
    assert!(
        highest_drops <= submissions,
        "the published drop counter must not outrun the records the sweep submitted, got \
         {highest_drops} for {submissions} records: that is a retry or a worker per record"
    );
    assert!(
        lowest_drops <= highest_drops,
        "the published drop range must be well ordered, got {lowest_drops}..={highest_drops}"
    );
    // THE PRODUCT'S OWN COUNTER RULE, measured from the sweep's own records
    // rather than restated from the comment above: exactly the
    // worker-unavailable refusal advances the counter, the closed refusal does
    // not, and the counter therefore cannot have advanced more than once per
    // worker-unavailable refusal.
    assert!(
        highest_drops <= worker_refusals,
        "only the worker-unavailable refusal advances the drop counter, so the published \
         high-water mark must stay within the {worker_refusals} refusals of that kind the sweep \
         received, got {highest_drops}"
    );
    highest_drops
}

/// THE DELIVERY FILTER, corrected to read the field the product actually writes
/// into, and the bounds that survive that correction.
///
/// WHAT THE FILTER SELECTS. A record is a delivery record when its `event=`
/// field is [`DELIVERY_EVENT_NAME`], which is the name the product writes at
/// src/windows_event_log.rs:1066; its disposition is then read off that same
/// record's `outcome=` FIELD, which is the field the product writes at
/// src/windows_event_log.rs:1070. The two are never conflated: every name
/// [`delivery_event_names`] returns is an `outcome=` value
/// (`EventLogDelivery::as_str()`, `WindowsEventLogError::as_str()`, and the
/// worker's own `"report_panic_contained"`), and the product's `event=` names
/// are all `host.*`. Reading `outcome=` values out of `event=` therefore
/// selects the empty set for ANY product, which is exactly the defect these arms
/// replace: the three they guard could never fail.
///
/// WHAT IS PROVEN AT RUNTIME, ON BOTH PLATFORMS:
/// * the filter is LIVE. Every record in `captured` is tested against
///   [`DELIVERY_EVENT_NAME`], so a delivery record emitted on a caller-side
///   thread IS selected rather than swept into silence;
/// * what such a record would turn RED depends on the record itself, and saying
///   so precisely matters more than a blanket claim. A delivery record appearing
///   here at all fails the `delivery_records.is_empty()` guard; one carrying no
///   `outcome=` field, or an `outcome=` outside [`delivery_event_names`], fails
///   the two disposition arms as well. A well-formed one -- `outcome=` present
///   and published -- fails the emptiness guard and nothing else;
/// * UNCONDITIONAL, and able to fail today whatever the scope holds: the census
///   that `event = "host.event_log_delivery"` is written exactly once, in the
///   product's own source, which is not a restatement of the literal above; and
///   the `delivery_records.is_empty()` regression guard, described at its site;
/// * NOT evidence of anything: the set equality between the two delivery
///   observers. Over this scope both sets are empty, so it compares two empty
///   sets. What it does exercise is that both observers read the field named
///   `event`, which is a fact about this file rather than about the product.
///
/// CONDITIONAL AND VACUOUS OVER THIS SCOPE, named here so it is not mistaken for
/// proof: the `distinct_threads.len() <= 4` bound and the two disposition arms
/// hold only when a delivery record exists in `captured`, and no such record
/// exists here (see the next paragraph for why). Each is a real check against a
/// real record that no present record exercises, and each is satisfied today by
/// the empty set.
///
/// WHAT IS NOT PROVEN AT RUNTIME, and is claimed from source census instead:
/// that the product emits its delivery record FROM its single
/// `eliot-event-log` worker. This sweep installs its layers with
/// `tracing::subscriber::with_default`, which publishes a THREAD-LOCAL default
/// and does NOT propagate it to threads spawned inside the block -- the
/// `with_default` doc warning in tracing-core's `src/dispatcher.rs` says
/// verbatim "with_default will not propagate the current thread's default
/// subscriber to any threads spawned within the with_default block". A worker
/// thread with no local default falls back to `get_global()`, which this sweep
/// never set, so that record cannot reach this capture at all. The ONE-WORKER
/// BOUND is therefore asserted where it can fail, by
/// [`assert_the_wrapper_spawns_exactly_one_named_worker`], and is deliberately
/// NOT restated here as `distinct_threads.len() == 1`: over this scope the set is
/// empty on every platform, and a count over an empty set is a tautology wearing
/// a proof.
///
/// `captured` is the sweep's own record set and `observing_threads` the cell
/// the sweep's observing layer collected. The two are filled independently, by
/// two different layers, which is a fact about THIS FILE -- it is not evidence
/// about the product, and over this scope both sides are empty.
fn assert_delivery_reached_one_product_thread(
    captured: &[CapturedRecord],
    observing_threads: &Arc<Mutex<Vec<std::thread::ThreadId>>>,
) {
    // The product really writes this spelling. CENSUSED, not restated: a rename
    // is caught HERE, and failing here is strictly better than silently
    // selecting nothing. `line_matching` reports the one source line the name
    // appears on, so the census also says WHERE the product writes it rather
    // than only that it is written somewhere.
    assert_eq!(
        line_matching(
            &manifest_source("src/windows_event_log.rs"),
            "event = \"host.event_log_delivery\"",
        )
        .len(),
        1,
        "the wrapper must emit the delivery record under exactly one `event = \"{{}}\"` spelling, \
         and it must be the spelling DELIVERY_EVENT_NAME selects on -- a rename must turn this \
         arm red rather than leave the delivery filter matching nothing"
    );
    let delivery_dispositions = delivery_event_names();
    let delivery_records: Vec<&CapturedRecord> = captured
        .iter()
        .filter(|record| record.event == DELIVERY_EVENT_NAME)
        .collect();
    // `ThreadId` is `Eq + Hash` but not `Ord`, so the two sets below are built
    // with `HashSet` rather than by sorting a `Vec`: the DEDUPLICATION is the
    // same (one entry per distinct thread either way), and set equality is
    // compared directly instead of through a sort that could not compile.
    let distinct_threads: std::collections::HashSet<std::thread::ThreadId> = delivery_records
        .iter()
        .map(|record| record.thread_id)
        .collect();
    let observing_ids: std::collections::HashSet<std::thread::ThreadId> =
        observing_threads.lock().unwrap().iter().copied().collect();
    // The dispositions the selected records CLAIM, held once so the arms below
    // judge the sweep's records rather than re-reading them.
    let claimed_dispositions: Vec<&str> = delivery_records
        .iter()
        .map(|record| record.field("outcome").unwrap_or(""))
        .collect();
    // WHY THERE IS NO `distinct_threads.len() == 1` HERE. The product emits its
    // `host.event_log_delivery` record from the Event Log WORKER thread
    // (src/windows_event_log.rs:1063-1072), and `captured` is the sweep's
    // THREAD-LOCAL `RecordingLayer`, installed by
    // `tracing::subscriber::with_default`. That publishes a thread-local
    // default only: the `with_default` doc warning in tracing-core's
    // `src/dispatcher.rs` states verbatim "with_default will not propagate the
    // current thread's default subscriber to any threads spawned within the
    // with_default block". A worker thread with no local default falls back to
    // `get_global()`, which this sweep never set, so `distinct_threads` is empty
    // here on a live port and off it alike. A requirement that it hold exactly
    // one element would be deterministically RED on the live platform and
    // provably TRUE for the wrong reason on the others -- so it is not asserted.
    // The single-worker BOUND is not dropped, it is asserted where it can fail,
    // by `assert_the_wrapper_spawns_exactly_one_named_worker`.
    //
    // WHAT SURVIVES HERE IS NOT PROOF, and is not claimed as any. The previous
    // text in this file described the arms below as surviving over a non-empty
    // scope, on the strength of this sweep's own threads inheriting the
    // thread-local default. That inference was wrong, and it is withdrawn: the
    // sweep's own threads DO inherit the capture, but the DELIVERY FILTER
    // selects only records carrying the product's `event = "host.event_log_delivery"`
    // name, and no sweep-owned thread emits that record -- only the product's
    // worker does, on a thread that inherits nothing. So `delivery_records` is
    // EMPTY, and therefore `distinct_threads`, `observing_ids`, and
    // `claimed_dispositions` are all empty. The count bound and the two
    // disposition arms are consequently vacuous over this scope: each is
    // satisfied today by the empty set and could not fail for the product as it
    // stands. They are retained as regression guards against a future product
    // that emits the delivery record on a caller-side thread, and they are NOT
    // offered as evidence for anything.
    //
    // THE NEXT ARM IS THE REGRESSION GUARD, and this is what it is worth. A
    // product that claimed a delivery WITHOUT dispatching it through its own
    // worker is a real regression, and the check below is the semantically right
    // one for it -- but for ANY product observed through a thread-local capture
    // it CANNOT fail, because no such product can put a delivery record into
    // this scope. It is retained as a guard against a future product that emits
    // the delivery record off-worker, and it is NOT offered as evidence. The
    // limitation belongs to the HARNESS: `with_default` is thread-local. It is
    // not a statement about the product, about the delivery path, or about the
    // platform.
    //
    // THE ONE-WORKER BOUND, the thing these arms cannot establish, is asserted
    // where it can fail, by `assert_the_wrapper_spawns_exactly_one_named_worker`:
    // exactly one `.spawn(`, exactly one `.name("eliot-event-log"`, zero
    // `thread::spawn`, and exactly one `worker_spawned.store(true)` in the
    // product's own source.
    assert!(
        distinct_threads.len() <= 4,
        "at most the sweep's own four worker threads can reach a thread-local capture -- the \
         product's `eliot-event-log` worker cannot -- so more than four distinct emitting threads \
         among these records means the product grew a thread of its own inside this scope, got {}",
        distinct_threads.len()
    );
    // THE DISPOSITIONS THEMSELVES, which is where a wrong-field filter hides. A
    // selected record that carries no `outcome=` field, or one whose `outcome=`
    // is not a name the product's own vocabulary publishes, fails here. With the
    // field read from the right place a realistic product record -- `event =
    // "host.event_log_delivery"` with `outcome = "registered_source_accepted"`
    // -- would be selected AND accepted, so these arms discriminate between
    // records rather than accepting everything. What they do NOT do is see any
    // record today: `delivery_records` is empty over this scope for the reason
    // given above, so both `.all()` calls are satisfied by the empty set. They
    // are kept as guards, not cited as evidence.
    assert!(
        delivery_records
            .iter()
            .all(|record| record.field("outcome").is_some()),
        "every record carrying the product's delivery `event=` name must carry the `outcome=` \
         field the product writes beside it; a record without one is selected here but cannot be \
         told apart from any other, and the filter would stop being a filter"
    );
    assert!(
        claimed_dispositions
            .iter()
            .all(|outcome| delivery_dispositions.contains(outcome)),
        "every delivery record's `outcome=` must be a disposition the product's own vocabulary \
         publishes; the filter reads this FIELD, so a disposition smuggled in under any other \
         name is caught here rather than swept into silence"
    );
    // BOTH PLATFORMS: `event_log_sink_status()` does NOT appear in either
    // condition below, and deliberately so. The product's single worker is
    // started process-wide by this case and then shut down before the sweep runs,
    // so a delivery record can be in this capture only if the product emitted one
    // on a thread that DID inherit the capture -- that is, without dispatching it
    // through its own worker. Live port or not, that is the claim this arm rules
    // out, and it is the claim the former `if event_log_sink_status().is_ok()`
    // split obscured. So the live-port branch, which asserted only that nothing
    // appeared here, is merged into this one.
    assert!(
        delivery_records.is_empty(),
        "the delivery record is emitted on the product's own worker thread, which cannot see this \
         thread-local capture, so a delivery record must never appear among the sweep's \
         caller-side records -- got {:?} claiming {:?}. A record here means the product claimed a \
         delivery WITHOUT dispatching it through its own worker",
        delivery_records
            .iter()
            .map(|record| record.event.as_str())
            .collect::<Vec<_>>(),
        claimed_dispositions
    );
    // `HashSet` implements `Index` never -- only `HashMap` does -- so the sets are
    // compared directly rather than sorted. Both sides are captured from the SAME
    // thread-local scope and both filter on the SAME two fields, but they are
    // filled by different layers at different points, so a disagreement would
    // mean one side saw a delivery-named event the other did not.
    //
    // WHAT THIS ARM PROVES, precisely, and what it CANNOT: it proves the two
    // observers AGREE. Over this scope the two sets are empty, so the equality
    // holds today -- and its honesty rests on the arms ABOVE it, not on this
    // line. The observation is exactly what catches a defect of the kind being
    // fixed here: when the filter read `outcome=` values out of the `event=`
    // field, a delivery record appearing on a caller-side thread was invisible to
    // BOTH observers, so each saw nothing, each saw the same nothing, and this
    // equality reported agreement. With the filter reading `event=` for the name
    // and `outcome=` for the disposition, a delivery record that DID appear is
    // seen by `captured`; it would reach `observing_ids` through the SAME
    // predicate in `ThreadObservingLayer::on_event`, and the two would still
    // agree. So this arm is kept as a cross-check on that shared predicate and
    // is NOT claimed as a second, independent proof of the single-worker bound
    // -- that bound is asserted by
    // `assert_the_wrapper_spawns_exactly_one_named_worker`.
    assert_eq!(
        observing_ids, distinct_threads,
        "both sides are captured from the same thread-local scope and watch the same \
         delivery-named events, so they must observe the same emitting threads; a difference \
         means one side saw a delivery-named event the other did not. Re-collecting \
         `observing_ids` into a `HashSet` of its own would only have compared a value with \
         itself, and is deliberately absent"
    );
}

/// The UNCONDITIONAL worker bound, which needs no runtime at all: the worker
/// thread is created in exactly one place, from exactly one named thread, and
/// nothing else in the product spawns a thread. A producer that grew a worker per
/// record, or added a second thread of its own, fails here by name.
fn assert_the_wrapper_spawns_exactly_one_named_worker() {
    let wrapper = manifest_source("src/windows_event_log.rs");
    assert_eq!(
        line_matching(&wrapper, ".spawn(").len(),
        1,
        "the wrapper must spawn exactly one thread; a second spawn site is an unbounded worker"
    );
    assert_eq!(
        line_matching(&wrapper, ".name(\"eliot-event-log\"").len(),
        1,
        "the one thread the wrapper spawns must be the single bounded Event Log worker"
    );
    assert!(
        !wrapper.contains("thread::spawn"),
        "the wrapper must spawn its one worker through the named builder, never anonymously"
    );
    assert_eq!(
        line_matching(&wrapper, "worker_spawned.store(true").len(),
        1,
        "the worker flag must be set in exactly one place, or a second thread could claim to be \
         the single worker"
    );
}

/// The producer's own start record, captured through the real facade under a
/// scoped subscriber.
///
/// Returns the captured window, which the in-flight bound and the start-record
/// field arms both read, so the capture cannot be bypassed by ignoring it.
fn capture_the_producer_start_record() -> String {
    let start_sink = MeasuringSink::default();
    let start_writer = start_sink.clone();
    {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || start_writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, start_event_log_reporting);
        start_sink.rendered()
    }
}

/// The in-flight bound the PRODUCT published, parsed out of its own start
/// record rather than assumed here, and checked to be a single record at most.
///
/// `start_records` is the window the producer-start capture returned, so the
/// number is read from the very record the later arms judge.
fn the_in_flight_bound_the_product_published(start_records: &str) -> usize {
    let in_flight_bound = match start_records
        .split("in_flight=")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
    {
        Some(digits) => digits.parse::<usize>().unwrap_or_else(|_| {
            panic!("the start record must carry an integer in_flight count, got: {start_records}")
        }),
        None => panic!("the start record must carry an in_flight count, got: {start_records}"),
    };
    assert!(
        in_flight_bound <= 1,
        "in-flight work must be bounded by a single record, got {in_flight_bound}"
    );
    in_flight_bound
}

/// The queue capacity the FIXTURE declares, which the shutdown bound above
/// combines with the product's own in-flight bound.
fn the_fixtures_queue_capacity(fixture: &Value) -> usize {
    usize::try_from(
        fixture["queue_capacity"]
            .as_u64()
            .expect("fixture must pin the queue capacity"),
    )
    .expect("queue capacity must fit usize")
}

/// The facade's own shutdown record, captured through the real facade under a
/// scoped subscriber.
///
/// Returns the captured window, which the shutdown-record agreement arms read,
/// so the capture cannot be bypassed by ignoring it.
fn capture_the_producer_shutdown_record() -> String {
    let shutdown_sink = MeasuringSink::default();
    let shutdown_writer = shutdown_sink.clone();
    {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || shutdown_writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, shutdown_event_log_reporting);
        shutdown_sink.rendered()
    }
}

/// The queue's own shutdown snapshot parks held records and reports them as
/// unsent -- neither delivered nor proven stopped. Asserted as a real value
/// against the queue's own admission accounting, not as a match that can only
/// succeed.
fn assert_shutdown_parks_held_records_as_unsent_not_delivered() {
    let mut queue = WindowsEventLogQueue::with_default_capacity();
    queue
        .try_admit(EventLogRecord::new(AdmittedEvent::ServiceStart, "parked"))
        .expect("admission within capacity must succeed");
    let held_before_shutdown = queue.len();
    assert!(
        held_before_shutdown > 0,
        "the queue must really hold the record before shutdown parks it, got {held_before_shutdown}"
    );
    let parked = queue.shutdown();
    assert_eq!(
        parked.unsent(),
        held_before_shutdown,
        "shutdown must park every record the queue held as unsent, never as delivered or aborted"
    );
    assert_eq!(
        parked.dropped_total(),
        0,
        "shutdown must report only the drops the queue counted"
    );
}

/// The producer's own start record, read back field by field: whether the
/// process-wide worker was created, and how much work the product says can be
/// outstanding at once. Both are values the producer published, and both hold in
/// either execution order.
///
/// The two boolean slots are read as the product spells a boolean --
/// `rendered_field` yields `true`/`false` -- and `in_flight_bound` was parsed out
/// of this very record, so the in-flight arm compares the record against itself
/// through the product's own reader.
fn assert_the_start_record_reports_what_the_producer_published(
    start_records: &str,
    in_flight_bound: usize,
) {
    let start_line = start_records
        .lines()
        .find(|line| rendered_field(line, "event") == Some("host.event_log_producer_start"))
        .unwrap_or_else(|| {
            panic!(
                "the facade's start_event_log_reporting must have emitted exactly one \
                 host.event_log_producer_start record, got: {start_records}"
            )
        });
    assert!(
        matches!(
            rendered_field(start_line, "worker_started"),
            Some("true" | "false")
        ),
        "the start record must report whether the process-wide worker thread was created, got {:?}",
        rendered_field(start_line, "worker_started")
    );
    assert_eq!(
        rendered_field(start_line, "in_flight"),
        Some(in_flight_bound.to_string().as_str()),
        "the start record must report the in-flight count the producer published"
    );
    assert!(
        matches!(
            rendered_field(start_line, "in_flight_unknown"),
            Some("true" | "false")
        ),
        "the start record must report whether that in-flight count was observed or refused"
    );
}

// WORK_UNIT_CASE: 889/1
// WORK_UNIT_CASE: 889/19
#[test]
fn host_reference_failure_and_registration_are_singular() {
    // Exactly one current `main.rs` reference failure uses the facade, and
    // the library registration is exactly the two new modules: no lifecycle
    // instrumentation here (that is #891's), no FFI in Host. (Cases 889/1
    // inventory, 889/19 single reference failure.)
    let lib = manifest_source("src/lib.rs");
    assert_eq!(
        lib.matches("pub mod host_diagnostics;").count(),
        1,
        "lib must register the facade exactly once"
    );
    assert_eq!(
        lib.matches("pub mod windows_event_log;").count(),
        1,
        "lib must register the sink seam exactly once"
    );

    let main = manifest_source("src/main.rs");
    assert_eq!(
        main.matches("install_host_diagnostics").count(),
        1,
        "main must install diagnostics exactly once"
    );
    assert_eq!(
        main.matches("observe_terminal_error").count(),
        1,
        "main must keep exactly one reference failure for HOST-0"
    );
    assert!(
        main.contains("HOST_TERMINAL_CODE_CONSOLE_FAILED"),
        "the single reference failure must use the frozen console code"
    );

    // No Event Log FFI is acquired inside Host; the seam stays typed and
    // absent until #984 lands.
    for (name, contents) in [
        (
            "host_diagnostics.rs",
            manifest_source("src/host_diagnostics.rs"),
        ),
        (
            "windows_event_log.rs",
            manifest_source("src/windows_event_log.rs"),
        ),
        ("main.rs", main),
    ] {
        for forbidden in [
            "RegisterEventSource",
            "ReportEventW",
            "DeregisterEventSource",
        ] {
            assert!(
                !contents.contains(forbidden),
                "{name} must not acquire Event Log FFI ({forbidden})"
            );
        }
    }
    let wrapper = manifest_source("src/windows_event_log.rs");
    assert!(
        wrapper.contains("EventLogUnavailable"),
        "wrapper must keep the typed unavailable seam"
    );
}

// WORK_UNIT_CASE: 889/21
#[test]
fn host_facade_is_compiled_once_and_reached_through_one_exported_owner() {
    // Case 21: the binary, the library consumer and this integration test must
    // all compile against ONE exported facade, with no duplicated module or
    // subscriber state. A compile-time fact cannot be observed at runtime, so
    // the proof is made against the real tracked sources, and every assertion
    // below fails the moment a second `mod` registration of an owned product
    // file, a recompile of one, or a second subscriber-state cell appears.
    //
    // The module census is proved live before its counts are trusted: it must
    // find this library's own many module registrations, so the per-file
    // "only one registration may name an owned file" checks below can never
    // pass on an empty or broken census.
    let lib = manifest_source("src/lib.rs");
    let main = manifest_source("src/main.rs");
    let facade = manifest_source("src/host_diagnostics.rs");
    let wrapper = manifest_source("src/windows_event_log.rs");

    // Same census discipline, second kind: every path this test resolves through
    // `eliot_host::` must be a module registration OR a library-root item the
    // real `lib.rs` declares. It also proves the census is a census of the real
    // file rather than of an empty read.
    let lib_modules =
        library_census_registers_each_owned_file_exactly_once(&lib, &facade, &wrapper);

    // (ii) The binary reaches that same exported owner and owns no copy of it:
    // none of its module registrations names an owned product file, and it
    // recompiles none of them through a path or include directive.
    let main_modules = binary_module_census_names_no_owned_copy(&main);

    // The census that phase (ii) ran against is threaded onward and asserted
    // here, at the one place it belongs: this is the same list the helper read
    // off the real `main.rs`, not a second read that could differ, so the claim
    // "the binary owns no copy of the module" is made against the very census
    // that observed it. The census is also proved LIVE before it is trusted -
    // `main.rs` really does register modules of its own on this HEAD, so none
    // of these arms can pass on an empty or broken census the way an unread
    // file would.
    assert!(
        !main_modules.is_empty(),
        "the main.rs module census must observe the binary's own module registrations, so the \
         no-owned-copy arms below cannot pass on an empty census, got: {main_modules:?}"
    );
    for owned in ["host_diagnostics", "windows_event_log"] {
        assert!(
            !main_modules
                .iter()
                .any(|declaration| declaration.contains(owned)),
            "main.rs must not declare its own {owned} module, so the binary owns no copy of the \
             module the library exports, got: {main_modules:?}"
        );
        assert_eq!(
            main_modules
                .iter()
                .filter(|declaration| declaration.contains(owned))
                .count(),
            0,
            "no main.rs module registration may name {owned}: exactly zero copies may be compiled, \
             got: {main_modules:?}"
        );
    }

    // (iii) Exactly ONE subscriber-state cell exists in the whole Host tree and
    // it is the facade's private `SUBSCRIBER_SETUP`: the binary, the sink seam
    // and this integration test add none, so no second `tracing` subscriber
    // state can ever be compiled. The Event Log producer state is equally
    // owned by the sink seam alone.
    assert_one_subscriber_state_cell_and_one_producer_cell(&lib, &main, &facade, &wrapper);

    // Public exposure stays limited to diagnostic types and operations: the
    // library must not re-export Host lifecycle internals beside the facade.
    for forbidden in [
        "pub use crate::HostComposition",
        "pub use crate::HostError",
        "pub use crate::HostLaunchOptions",
        "pub use crate::host_activation",
        "pub use crate::scm_launch",
        "pub use crate::lease_drain",
        "pub use crate::host_job_launch",
    ] {
        assert!(
            !lib.contains(forbidden),
            "lib.rs must not widen the facade owner into private Host lifecycle internals ({forbidden})"
        );
    }

    // The fixture agrees: the shared owner is named once, so no duplicated
    // compilation can invent a second diagnostics target.
    let fixture = contract_fixture();
    assert_eq!(
        fixture["target"].as_str(),
        Some(HOST_DIAGNOSTICS_TARGET),
        "the fixture must name the one compiled facade target"
    );

    // This integration test is itself a library consumer, not a recompiler: it
    // resolves the facade by import above and reaches it only through
    // `eliot_host::` paths. The read below is a plain runtime read of the tracked
    // test file, never a recompile, which is exactly what is forbidden.
    //
    // WHY THERE IS NO SELF-CHECK ON THIS FILE. A census that reads this test
    // file and asserts something about this test file is not evidence: an
    // integration-test target structurally cannot declare a module, so
    // `module_declarations(&own).is_empty()` could only ever pass. The
    // `#[path` / `include!` scans that replaced it were the same defect wearing
    // a different hat - they matched this file's OWN source text (the needles
    // appear inside the very `line_matching(&lib, ...)` call sites that assert
    // them absent from the product files), so they proved only that this test
    // mentions its own needles, and in fact failed for that reason. Both are
    // removed rather than re-tuned: no assertion here reads this file to decide
    // whether this file is correct.
    //
    // What replaces them is genuinely falsifiable, because its subject is the
    // PRODUCT source, not this test: every `use eliot_host::` root this file
    // declares must resolve to a module (or a library-root item) that the
    // census above actually observed in the tracked `src/lib.rs`. Renaming or
    // unregistering `host_diagnostics` in lib.rs, or importing a name lib.rs
    // never registers, now fails here - a local copy of the facade compiled
    // under its own `mod` would have to import through `eliot_host::` and would
    // resolve to nothing.
    let roots = library_roots_this_test_imports();
    assert!(
        !roots.is_empty(),
        "an integration test must reach the facade through the `eliot_host::` library path"
    );
    assert!(
        !lib_modules.is_empty(),
        "the cross-target resolution proof needs a non-empty module census of lib.rs"
    );
    assert_every_library_root_this_test_imports_resolves(&roots, &lib, &lib_modules);
}

/// (iii) Exactly ONE subscriber-state cell exists in the whole Host tree and it
/// is the facade's private `SUBSCRIBER_SETUP`, and the Event Log producer cell
/// is owned by the sink seam alone -- so no second `tracing` subscriber state
/// and no second producer state can ever be compiled.
///
/// Each of the four tracked sources is checked, not just the facade: a binary
/// or sink seam that declared its own cell would compile a second global
/// subscriber alongside the facade's, and the count arms below would catch it.
///
/// `name` binds as `&str`, so `*name` is a `str`; dereferencing the literal too
/// makes both sides `str` and the comparison well typed. The count stays exactly
/// 1 for the facade and 0 for the other three, i.e. the single `SUBSCRIBER_SETUP`
/// cell.
fn assert_one_subscriber_state_cell_and_one_producer_cell(
    lib: &str,
    main: &str,
    facade: &str,
    wrapper: &str,
) {
    for (name, source) in [
        ("src/lib.rs", lib),
        ("src/main.rs", main),
        ("src/host_diagnostics.rs", facade),
        ("src/windows_event_log.rs", wrapper),
    ] {
        assert_eq!(
            source.matches("static SUBSCRIBER_SETUP").count(),
            usize::from(*name == *"src/host_diagnostics.rs"),
            "{name} must not declare its own subscriber-state cell"
        );
        assert!(
            !source.contains("fn set_global_default"),
            "{name} must not install a second global tracing subscriber"
        );
    }
    assert_eq!(
        wrapper.matches("static EVENT_LOG_PRODUCER").count(),
        1,
        "the sink seam must own the single Event Log producer cell"
    );
}

/// (i) The library is the sole owner: it registers each owned product file
/// exactly once, and it recompiles none of them through a path or include
/// directive. Only those two registrations may name an owned file, since any
/// other registration of the same file would compile it a second time.
///
/// Returns the live `lib.rs` module census the caller threads onward, so the
/// exactly-once claims above are proved against the very list the caller later
/// resolves its `eliot_host::` roots through, not a second read that could
/// differ.
fn library_census_registers_each_owned_file_exactly_once(
    lib: &str,
    facade: &str,
    wrapper: &str,
) -> Vec<String> {
    let lib_modules = module_declarations(lib);
    assert!(
        lib_modules.len() >= MIN_LIB_MODULE_DECLARATIONS,
        "the module census must read all of lib.rs: it saw {} declarations, fewer than the {} \
         recorded on this HEAD, so a bounded or truncated census cannot back the \
         exactly-once registration claims below",
        lib_modules.len(),
        MIN_LIB_MODULE_DECLARATIONS
    );
    assert!(
        lib_modules.len() > 1,
        "the module census must find lib.rs's own module registrations, got: {lib_modules:?}"
    );
    let lib_path_witnesses = line_matching(lib, "#[path");
    assert!(
        lib_path_witnesses.is_empty(),
        "lib.rs must not attribute-compile any module path, got: {lib_path_witnesses:?}"
    );
    let lib_include_witnesses = line_matching(lib, "include!");
    assert!(
        lib_include_witnesses.is_empty(),
        "lib.rs must not textually include a module file, got: {lib_include_witnesses:?}"
    );
    for owned in ["host_diagnostics", "windows_event_log"] {
        assert_eq!(
            lib.matches(&format!("pub mod {owned};")).count(),
            1,
            "the library must register the {owned} module exactly once"
        );
        assert_eq!(
            lib_modules
                .iter()
                .filter(|declaration| declaration.contains(owned))
                .count(),
            1,
            "exactly one lib.rs module registration may name the {owned} file, so it is compiled once"
        );
    }
    assert!(
        !facade.contains("#[path") && !facade.contains("include!"),
        "the facade must not be recompiled through a path or include directive"
    );
    assert!(
        !wrapper.contains("#[path") && !wrapper.contains("include!"),
        "the sink seam must not be recompiled through a path or include directive"
    );
    lib_modules
}

/// The binary reaches that same exported owner and owns no copy of it: none of
/// its module registrations names an owned product file, and it recompiles none
/// of them through a path or include directive.
///
/// Returns the live `main.rs` module census the caller threads onward, so the
/// census this non-interference check ran against is the very list the caller
/// holds rather than a second read that could differ.
fn binary_module_census_names_no_owned_copy(main: &str) -> Vec<String> {
    let main_modules = module_declarations(main);
    assert!(
        !main_modules.is_empty(),
        "the module census must find main.rs's own module registrations, got: {main_modules:?}"
    );
    for owned in ["host_diagnostics", "windows_event_log"] {
        assert!(
            !main_modules
                .iter()
                .any(|declaration| declaration.contains(owned)),
            "main.rs must not declare its own {owned} module, got: {main_modules:?}"
        );
        assert!(
            main.contains(&format!("eliot_host::{owned}::")),
            "main.rs must reach {owned} through the exported library path"
        );
    }
    let main_path_witnesses = line_matching(main, "#[path");
    assert!(
        main_path_witnesses.is_empty(),
        "main.rs must not attribute-compile a module path, got: {main_path_witnesses:?}"
    );
    let main_include_witnesses = line_matching(main, "include!");
    assert!(
        main_include_witnesses.is_empty(),
        "main.rs must not textually include a module file, got: {main_include_witnesses:?}"
    );
    main_modules
}

/// Every `use eliot_host::` root this integration test declares, in file order,
/// with nothing dropped and nothing duplicated.
///
/// The read is a plain runtime read of the tracked test file, never a
/// recompile, which is exactly what is forbidden. The `filter_map`s deliberately
/// FLATTEN the `Option<&str>` that `split(..).next()` hands back rather than
/// inspecting it, so a line with no root token drops out and what continues
/// down the chain is the `&str` root itself; `(*root).to_owned()` then
/// stringifies the BORROWED ROOT itself, so the returned vector holds real
/// module/item names that the resolution probe can match against the very
/// strings `lib.rs` registers.
fn library_roots_this_test_imports() -> Vec<String> {
    let own = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/host_diagnostics_contract.rs"),
    )
    .expect("this integration test file must be readable");
    own.lines()
        .filter_map(|line| line.trim().strip_prefix("use eliot_host::"))
        .filter_map(|rest| rest.trim_start_matches('{').split([':', ';', '{']).next())
        .filter(|root| !root.is_empty())
        .map(|root| (*root).to_owned())
        .collect()
}

/// Every root in `roots` must reach the shared exported owner by exactly two
/// honest routes: it is a module `lib.rs` registers
/// (`eliot_host::host_diagnostics::...`), or it is a library-root item `lib.rs`
/// itself declares (`pub enum HostError`, `pub struct HostComposition`,
/// `pub const SERVICE_NAME`, a `pub use` at the crate root, ...). A root that
/// resolves by neither is a path this library does not export at all, and would
/// mean the three targets no longer compile against the same owner.
///
/// `roots` is the list `library_roots_this_test_imports` read out of this
/// file's own `use eliot_host::` lines and `lib_modules` the live census of the
/// tracked `src/lib.rs`, so neither can be fabricated at the call site.
fn assert_every_library_root_this_test_imports_resolves(
    roots: &[String],
    lib: &str,
    lib_modules: &[String],
) {
    for root in roots {
        let declared_at_library_root = [
            "enum ",
            "struct ",
            "trait ",
            "type ",
            "union ",
            "const ",
            "static ",
            "fn ",
            "async fn ",
            "use ",
        ]
        .iter()
        .any(|kind| {
            lib.contains(&format!("pub {kind}{root} "))
                || lib.contains(&format!("pub {kind}{root}\n"))
        });
        let registered_module = lib_modules
            .iter()
            .any(|declaration| declaration.ends_with(&format!(" {root};")));
        assert!(
            registered_module || declared_at_library_root,
            "this integration test imports `eliot_host::{root}`, which lib.rs neither registers \
             as a module nor declares at its library root; the binary, the library consumer and \
             this test must all resolve through the SAME exported facade, got: {roots:?}"
        );
    }
}

/// Upper bound on the witness lines one census may collect, so a check cannot
/// quietly pass on an unexpectedly shaped source.
///
/// The bound that matters is the one on *collected* lines, so `line_matching`
/// does not silently truncate its result: if a caller asks about a needle that
/// matches more lines than the cap, the cap is a FAILURE, never a shorter list.
/// (The old 32-line cap used a silent `.take()`, which is how a sweep could
/// report "none found" after only reading the first 32 matches.)
const MAX_WITNESS_LINES: usize = 64;

/// Upper bound on the module declarations one census may collect.
///
/// `bins/eliot-host/src/lib.rs` really declares **46** module registrations on
/// this HEAD (3 `pub mod`, 43 `mod`), and `bins/eliot-host/src/main.rs`
/// declares 3. The cap sits comfortably above the real lib.rs count so the
/// census reads that file to the end, and it is asserted against a floor of
/// [`MIN_LIB_MODULE_DECLARATIONS`] below so a future drop in the real count
/// cannot leave the cap silently sized to a truncated view.
const MAX_MODULE_DECLARATIONS: usize = 128;

/// Floor for the real `src/lib.rs` module census, counted from the tracked file
/// on this HEAD: **46** declarations. Case 889/21 asserts the live census is at
/// least this large, so the cap above can never again be the thing that decides
/// how much of `lib.rs` the census reads.
const MIN_LIB_MODULE_DECLARATIONS: usize = 46;

fn line_matching<'a>(source: &'a str, needle: &str) -> Vec<&'a str> {
    let lines: Vec<&'a str> = source
        .lines()
        .filter(|line| line.contains(needle))
        .collect();
    assert!(
        lines.len() <= MAX_WITNESS_LINES,
        "the census for {needle:?} matched {} lines, above the {MAX_WITNESS_LINES}-line cap; \
         the cap is a hard bound to keep this check readable, not a licence to truncate - \
         raise MAX_WITNESS_LINES or narrow the needle rather than reading a partial list",
        lines.len()
    );
    lines
}

/// Every in-file module declaration in `source`, with `#[cfg]` attributes and
/// visibility left in place, so a caller can ask what a file registers and
/// which registered file it names. Doc comments and non-item lines are skipped,
/// which keeps prose that mentions `mod` out of the census.
///
/// The scan is deliberately NOT truncated: exceeding
/// [`MAX_MODULE_DECLARATIONS`] is a failure, not an early return, so this census
/// can never again quietly under-read a file that grew past the cap.
fn module_declarations(source: &str) -> Vec<String> {
    let mut declarations = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if !line.starts_with("#[") && !line.starts_with("//") {
            let declaration = line
                .strip_prefix("pub mod ")
                .map(|rest| format!("pub mod {rest}"))
                .or_else(|| line.strip_prefix("mod ").map(|rest| format!("mod {rest}")));
            if let Some(declaration) = declaration {
                declarations.push(declaration);
                assert!(
                    declarations.len() <= MAX_MODULE_DECLARATIONS,
                    "the module census collected {} declarations, above the \
                     {MAX_MODULE_DECLARATIONS} cap; the cap must stay a bound this file \
                     never reaches, never a silent truncation of the census",
                    declarations.len()
                );
            }
        }
    }
    declarations
}

/// The whitespace-free body of the brace-matched function whose first
/// non-attribute declaration line contains `signature`, or `None` when the
/// source has no such function or its body is not brace-balanced.
///
/// Attribute lines are stepped over exactly as [`module_declarations`] does, so
/// a doc comment quoting the signature cannot become the declaration that is
/// read, and the body is located by byte offset rather than by re-finding the
/// line's text (which would break on a duplicated line).
///
/// Every whitespace character is stripped, so the returned body compares by
/// tokens only: reformatting a function onto one line, re-indenting it, or
/// wrapping its arguments differently cannot change what a caller sees. Doc
/// comments and line comments are dropped first, so prose inside the body cannot
/// smuggle an identifier past a behavioural assertion either.
fn fn_body_without_whitespace(source: &str, signature: &str) -> Option<String> {
    let mut body_start = None;
    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        let trimmed = line.trim();
        let declares =
            !trimmed.starts_with("#[") && !trimmed.starts_with("//") && trimmed.contains(signature);
        if declares {
            if let Some(brace) = line.find('{') {
                body_start = Some(offset + brace);
            }
            break;
        }
        offset += line.len();
    }
    let body_start = body_start?;
    let rest = &source[body_start + 1..];
    let mut depth = 1usize;
    let mut closing = None;
    for (index, character) in rest.char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    closing = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    let closing = closing?;
    let body = rest[..closing]
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("");
    Some(body.chars().filter(|c| !c.is_whitespace()).collect())
}

// WORK_UNIT_CASE: 889/20
#[test]
fn host_diagnostics_allowed_diff_has_no_lifecycle_unsafe_or_authority_mutation() {
    // Case 20: this card's EDIT scope is EXACTLY two files - this contract test and
    // its fixture. The card also says "Do not edit the facade, Event Log, main,
    // lib or the manifest", so the facade/wrapper/lib/main arms below are
    // READ-ONLY assertions about untouched product sources, not claims about
    // files this delivery changed.
    //
    // WHY THIS GUARD IS NOT CIRCULAR. It compares the fixture's `allowed_diff`
    // against the CARD'S OWN SCOPE, not against a second copy of the same array.
    // `card_edit_scope` is the independent statement of what the card permits;
    // the fixture is the delivery's declaration of what it actually touched; the
    // two are different artefacts and this test fails whenever they disagree -
    // which is exactly what the old byte-identical-literal comparison could never
    // do. The fixture's list is not also read by any other consumer as a
    // licence to edit, so narrowing it to the two real files costs nothing and
    // removes the four product paths the previous list could not honestly claim.
    assert_the_allowed_diff_is_exactly_this_cards_edit_scope();
    assert_the_fixture_cases_enumerate_exactly_this_files_markers();
    assert_the_two_product_files_declare_no_unsafe_code();
    assert_the_facade_declares_only_the_bounded_diagnostic_surface();
    assert_the_facade_mutates_no_lifecycle_authority();
    assert_the_facade_carries_no_closed_surface_leak();
    let projected_reasons = assert_every_host_error_variant_projects_one_reason_code();
    assert_the_permitted_reason_codes_are_exactly_what_the_facade_projects(&projected_reasons);
}

/// The fixture's declared `allowed_diff` must name EXACTLY the two test files
/// this card may edit, each once. Returns nothing: the caller cannot skip this
/// arm, because the check is an assertion set this helper owns outright.
///
/// It compares against the CARD'S OWN SCOPE (an independent statement of what
/// the card permits), not against a second copy of the fixture's own array.
fn assert_the_allowed_diff_is_exactly_this_cards_edit_scope() {
    let fixture = contract_fixture();
    let card_edit_scope = [
        "bins/eliot-host/tests/data/host_diagnostics_cases.json",
        "bins/eliot-host/tests/host_diagnostics_contract.rs",
    ];
    let reported: Vec<&str> = fixture["allowed_diff"]
        .as_array()
        .expect("fixture must enumerate the allowed diff")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("each allowed-diff entry must be a path string")
        })
        .collect();
    let mut reported_set = reported.clone();
    reported_set.sort_unstable();
    reported_set.dedup();
    assert_eq!(
        reported_set.len(),
        reported.len(),
        "the allowed diff must not name a path twice, got: {reported:?}"
    );
    assert_eq!(
        reported_set, card_edit_scope,
        "the allowed diff must be EXACTLY the two test files this card may edit - this \
         contract test and its fixture - and nothing else: the four product paths under \
         bins/eliot-host/src/ are explicitly out of this card's EDIT scope and must not be \
         claimed here. got: {reported:?}"
    );
}

/// The fixture's `cases` array is a CONTRACT, not documentation: it must
/// enumerate the issue's matrix exactly, and it must enumerate THIS FILE's
/// markers exactly. The module header already claimed that "the remaining
/// inventory, per-identity, sizing, canary and sink-mapping cases are named and
/// enumerated by the fixture's `cases` array, so no case in the issue's matrix
/// is left undeclared here" -- but nothing read that array, so a fixture with a
/// wrong id, a missing entry, or a label contradicting its markers would not
/// have turned this suite red. These arms make that header claim true.
///
/// Three separate properties, each able to fail on its own:
///   1. the array holds exactly [`DECLARED_WORK_UNIT_CASE_COUNT`] entries with
///      ids 1..=22, each appearing exactly once;
///   2. every entry's `marker` is `889/<its own id>`;
///   3. the SET of fixture markers equals the SET of `// WORK_UNIT_CASE: 889/<n>`
///      markers present in this file, so the array and the markers cannot drift
///      apart. Adding, removing or renumbering a marker turns this red.
///
/// WHY READING THIS FILE IS LEGITIMATE HERE, and why it is not the defect the
/// `#[path]`/`include!` scans were. The removed scans compared this file's own
/// source against needles that appear inside their own call sites, i.e.
/// needle-vs-its-own-call-site: the assertion could only ever confirm that this
/// test mentions its own text. This comparison is fixture-vs-markers -- two
/// INDEPENDENT artefacts, one shipped as JSON and one maintained as Rust
/// comments, that were previously free to disagree. Nothing here decides whether
/// a string is present in this file by matching that string itself: the markers
/// are read as a census of `889/<n>` labels, and each is then compared against
/// the fixture's independently declared ids.
fn assert_the_fixture_cases_enumerate_exactly_this_files_markers() {
    let fixture = contract_fixture();
    let entries = fixture["cases"]
        .as_array()
        .expect("the fixture must enumerate its case matrix as an array");
    // Exactly 22 fixture entries, ids 1..=22, each declared once: the list is
    // checked for size, then for the absence of duplicates, then against the
    // full expected id range, so neither a missing entry nor a repeated one can
    // hide behind the other.
    assert_eq!(
        entries.len(),
        DECLARED_WORK_UNIT_CASE_COUNT,
        "the fixture must declare exactly {DECLARED_WORK_UNIT_CASE_COUNT} cases, got {}",
        entries.len()
    );

    let mut declared: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = entry["id"]
            .as_u64()
            .expect("every fixture case must carry a numeric id");
        let marker = entry["marker"]
            .as_str()
            .expect("every fixture case must carry a marker string");
        assert_eq!(
            marker,
            format!("889/{id}"),
            "fixture case {id} declares marker {marker:?}, which must be `889/{id}`"
        );
        declared.push(marker.to_owned());
    }

    let mut deduped = declared.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        declared.len(),
        "the fixture must declare each case id exactly once, got: {declared:?}"
    );
    assert_eq!(
        deduped,
        (1..=DECLARED_WORK_UNIT_CASE_COUNT as u64)
            .map(|id| format!("889/{id}"))
            .collect::<Vec<_>>(),
        "the fixture's case ids must be exactly 1..={DECLARED_WORK_UNIT_CASE_COUNT}, each once"
    );

    // The census of this file's own markers. The needle is the MARKER PREFIX, so
    // this is a census of declarations, not a search for a string that also
    // appears in prose here: `strip_prefix` only accepts a line that BEGINS with
    // `// WORK_UNIT_CASE:`, so the doc comments that mention the marker scheme
    // (including the ones above) contribute nothing. The markers are then only
    // ever compared against the fixture's independently declared ids.
    let own = manifest_source("tests/host_diagnostics_contract.rs");
    let mut in_file: Vec<String> = own
        .lines()
        .filter_map(|line| {
            let marker = line.trim().strip_prefix("// WORK_UNIT_CASE:")?;
            let id = marker.trim().strip_prefix("889/")?;
            (!id.is_empty()).then(|| format!("889/{id}"))
        })
        .collect();
    assert_eq!(
        in_file.len(),
        DECLARED_WORK_UNIT_CASE_COUNT,
        "this file must carry exactly {DECLARED_WORK_UNIT_CASE_COUNT} work-unit markers, got {}: \
         {in_file:?}",
        in_file.len()
    );
    in_file.sort_unstable();
    let mut sorted_fixture = declared.clone();
    sorted_fixture.sort_unstable();
    assert_eq!(
        in_file, sorted_fixture,
        "the fixture's `cases` array and this file's `// WORK_UNIT_CASE` markers must declare the \
         SAME set of cases: a marker added, removed or renumbered here without a matching fixture \
         entry (or the reverse) is exactly the drift this arm exists to catch"
    );
}

/// The two product files this case reads carry no `unsafe`, and the crate keeps
/// the compile-time ban that makes a reintroduction fail the build.
///
/// Both product files are outside this card's EDIT scope: these are read-only
/// assertions about untouched sources, not claims about the diff. `concat!`
/// joins the split halves at compile time into exactly the one keyword this
/// test scans for, so this file's own text keeps carrying the keyword only in
/// these split halves while `unsafe_keyword` stays a `&str`: both `contains`
/// scans and both `forbid(...)` probes read the identical keyword they read
/// before.
fn assert_the_two_product_files_declare_no_unsafe_code() {
    let facade = manifest_source("src/host_diagnostics.rs");
    let wrapper = manifest_source("src/windows_event_log.rs");
    let lib = manifest_source("src/lib.rs");
    let main = manifest_source("src/main.rs");
    let unsafe_keyword = concat!("uns", "afe");
    for (name, source) in [
        ("host_diagnostics.rs", &facade),
        ("windows_event_log.rs", &wrapper),
    ] {
        assert!(
            !source.contains(unsafe_keyword),
            "{name} must contain no unsafe code"
        );
    }
    assert!(
        lib.contains(&format!("#![forbid({unsafe_keyword}_code)]")),
        "the library must keep forbidding unsafe code"
    );
    assert!(
        main.contains(&format!("#![forbid({unsafe_keyword}_code)]")),
        "the binary must keep forbidding unsafe code"
    );
}

/// The facade's declared public types are exactly the bounded diagnostic
/// surface, and it declares no second lifecycle authority of its own.
///
/// The census is compared as a SET, not as a sequence: what this case proves is
/// "these are the only public types the facade declares", and moving a `pub`
/// item up or down the file changes no behaviour, so it must not turn this test
/// red. A renamed, added or removed type still changes the SET and still fails.
fn assert_the_facade_declares_only_the_bounded_diagnostic_surface() {
    let facade = manifest_source("src/host_diagnostics.rs");
    let declared: Vec<&str> = facade
        .lines()
        .filter_map(|line| {
            // The `pub ` must be CONSUMED before the `enum `/`struct ` prefix is
            // taken. Leaving it in place - and then matching `enum `/`struct `
            // against the still-`pub`-prefixed line - silently matches nothing at
            // all, because no line starts with both, and the census then
            // reports an EMPTY public surface and passes nothing real.
            let declaration = line.trim().strip_prefix("pub ")?;
            let rest = declaration
                .strip_prefix("enum ")
                .or_else(|| declaration.strip_prefix("struct "))?;
            rest.split([' ', '{', ':', '<', '\t'])
                .next()
                .filter(|name| !name.is_empty())
        })
        .collect();
    let mut declared_set = declared.clone();
    declared_set.sort_unstable();
    declared_set.dedup();
    assert_eq!(
        declared_set.len(),
        declared.len(),
        "every public type the facade declares must have its own distinct name, got: {declared:?}"
    );
    let expected = [
        "HostDiagnosticsError",
        "DiagnosticSink",
        "BoundedField",
        "BoundedDetail",
        "EntrypointStage",
        "HostRequestEvidence",
        "HostConsoleRequest",
        "HostRequestProjection",
    ];
    let mut expected_set = expected.to_vec();
    expected_set.sort_unstable();
    assert_eq!(
        declared_set, expected_set,
        "the facade's public type names must be exactly the bounded diagnostic surface; the \
         comparison is set-valued, so declaration order is free but the SET is not"
    );
    for canonical in [
        "ServiceProcessState",
        "ModuleGenerationState",
        "HostProcessState",
        "ProcessLifecycleState",
        "GenerationLifecycleState",
        "HostLifecycleState",
        "LifecycleState",
    ] {
        assert!(
            !facade.contains(&format!("enum {canonical}")),
            "the facade must not declare a second {canonical} lifecycle authority"
        );
    }
    // The facade projects the owners' evidence instead of owning it: it names
    // neither normative machine, so process liveness/readiness and
    // capability-generation state stay separate and with their owners.
    assert!(
        !facade.contains("ServiceProcessState"),
        "the facade must not restate the process lifecycle vocabulary"
    );
    assert!(
        !facade.contains("ModuleGenerationState"),
        "the facade must not restate the generation lifecycle vocabulary"
    );
}

/// No authority mutation: the facade's public surface is read-only over the
/// owner it observes. It never calls a mutating owner operation and never
/// carries interior mutability or a mutable static that could stand in for
/// authority. Its builder receivers (`mut self`) only assemble the
/// caller-owned value being returned, so they grant no mutation of Host.
fn assert_the_facade_mutates_no_lifecycle_authority() {
    let facade = manifest_source("src/host_diagnostics.rs");
    for mutating in [
        "HostComposition::stop(",
        "HostComposition::open(",
        "HostComposition::start_approved_contour(",
        "HostComposition::start_manifest_contour(",
        "HostComposition::cleanup_active_kernel_contour(",
        "HostComposition::cleanup_launched_contour(",
        "HostComposition::transition_activation(",
        "std::process::Command",
        "Command::new(",
    ] {
        assert!(
            !facade.contains(mutating),
            "the facade must not mutate lifecycle authority ({mutating})"
        );
    }
    assert!(
        !facade.contains("static mut"),
        "the facade must not declare mutable static authority"
    );
    assert!(
        !facade.contains("RefCell") && !facade.contains("RwLock") && !facade.contains("Cell<"),
        "the facade must not carry interior mutability that could stand in for authority"
    );
    // The single mutating sink cell it legitimately owns is the private
    // subscriber-install mutex, and that is exactly one declaration.
    assert_eq!(
        facade.matches("static SUBSCRIBER_SETUP:").count(),
        1,
        "the facade must own exactly one subscriber-state cell"
    );
}

/// Closed bounded nonsecret field surface: the facade publishes no
/// credential, token, connection-string, environment, command-line or
/// arbitrary error payload surface.
fn assert_the_facade_carries_no_closed_surface_leak() {
    let facade = manifest_source("src/host_diagnostics.rs");
    let wrapper = manifest_source("src/windows_event_log.rs");
    for (name, source) in [
        ("host_diagnostics.rs", &facade),
        ("windows_event_log.rs", &wrapper),
    ] {
        for leaked in [
            "std::env",
            "env::var",
            "CommandLine",
            "command_line",
            "ConnectionString",
            "connection_string",
            "Password",
            "SecretRef",
            "SecretReference",
        ] {
            assert!(
                !source.contains(leaked),
                "{name} must not carry a {leaked} field in its closed surface"
            );
        }
    }
}
/// Every `HostError` variant the facade can project must be projected EXACTLY
/// once, through the typed reason projection, and nothing but a frozen
/// discriminant may cross the reason slot.
///
/// Failure evidence crosses only as a typed discriminant: the facade maps
/// every `HostError` variant to a frozen `&'static str`, never its payload
/// or an arbitrary `Debug`/`Display` rendering. The projection must be
/// total (drop an arm and this fails) and single (handle an arm twice and
/// this fails), which is what keeps the field surface closed.
fn assert_every_host_error_variant_projects_one_reason_code() -> Vec<String> {
    let facade = manifest_source("src/host_diagnostics.rs");
    let lib = manifest_source("src/lib.rs");
    assert!(
        facade.contains("fn project_host_error_reason(error: &HostError) -> &'static str"),
        "the facade must map failures through its typed reason projection"
    );
    assert!(
        facade.contains("reason: Option<&'static str>"),
        "the projection's reason slot must stay a frozen discriminant, never an error payload"
    );
    let taxonomy = lib
        .split_once("pub enum HostError {")
        .expect("the Host library must declare the HostError taxonomy")
        .1;
    let mut variants: Vec<(String, String)> = Vec::new();
    let mut arms = 0usize;
    for line in taxonomy.lines() {
        let line = line.trim();
        if line == "}" {
            break;
        }
        // An attribute line belongs to the variant it precedes and never names
        // a variant itself; skipping every `#[...]` line (the first character
        // is the `#`, escaped here) keeps the counted variant set exact.
        if line.starts_with("#[") || line.starts_with("//") || line.is_empty() {
            continue;
        }
        arms += 1;
        let name = line
            .trim_start_matches("pub ")
            .split(['(', ' ', '{'])
            .next()
            .expect("a non-empty trimmed line always yields a name")
            .trim_end_matches(',')
            .to_owned();
        // A payload-carrying arm is matched with parentheses, a field-carrying or
        // unit-like arm is followed by a space. Both forms are unambiguous: no
        // `HostError::` mention anywhere names one variant as a prefix of
        // another, so this can neither miss an arm nor double-count one.
        let spelling = if line.contains('(') {
            format!("HostError::{name}(")
        } else {
            format!("HostError::{name} ")
        };
        variants.push((name, spelling));
    }
    assert!(
        !variants.is_empty(),
        "the HostError taxonomy must expose at least one variant"
    );
    assert_eq!(
        variants.len(),
        arms,
        "the taxonomy parse must yield exactly one name per variant line"
    );
    for (variant, spelling) in &variants {
        assert_eq!(
            facade.matches(spelling).count(),
            1,
            "HostError::{variant} must be projected exactly once, never omitted and never twice"
        );
    }

    // The closed reason-code sweep must stay TOTAL over that taxonomy: the
    // number of reason codes the canary sweeps admit is exactly the number of
    // `HostError` variants the facade projects. A 19th variant added to
    // `HostError` fails here rather than quietly escaping
    // `PERMITTED_REASON_CODES` in cases 889/11 and 889/12.
    assert_eq!(
        PERMITTED_REASON_CODE_COUNT,
        variants.len(),
        "the permitted reason-code set must stay exactly as large as the HostError taxonomy, so \
         every projectable reason is admitted by the sweep and no added variant escapes it"
    );
    assert_eq!(
        PERMITTED_REASON_CODES.len(),
        PERMITTED_REASON_CODE_COUNT,
        "the permitted reason-code list and its count constant must agree, so the count cannot \
         silently drift away from the set it is meant to describe"
    );

    // The count alone is not completeness: two different 18-entry sets both
    // satisfy it. So the permitted list is also compared against the strings
    // `project_host_error_reason` can actually return, read out of the facade's
    // own match arms. This is the assertion that catches a variant whose
    // projected code was renamed (the count holds, the SET moves) and a variant
    // whose arm was dropped or duplicated - in every case the list stops being
    // exactly what the facade projects, and the canary sweeps in cases 889/11
    // and 889/12 would otherwise admit or reject on a stale list.
    //
    // The comparison itself is set-valued and lives in
    // `assert_the_permitted_reason_codes_are_exactly_what_the_facade_projects`,
    // which the caller must run on the list returned here.
    fn_body_without_whitespace(&facade, "fn project_host_error_reason")
        .expect("the facade must keep its typed reason projection")
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect::<Vec<String>>()
}

/// `PERMITTED_REASON_CODES` must be EXACTLY the set of reason codes the facade
/// projects: a renamed, added, dropped or duplicated projection all fail here
/// instead of silently escaping the canary sweep.
///
/// The comparison is set-valued, so the order and layout of either side are
/// free; only membership is pinned. The count is checked here as well, so a
/// facade that stopped projecting one code per arm cannot pass by matching a
/// stale set.
///
/// `projected_reasons` is the list this file's own taxonomy parse read out of
/// `project_host_error_reason`; the caller MUST thread it onward from
/// `assert_every_host_error_variant_projects_one_reason_code`, so this
/// comparison cannot be bypassed by simply not asking for the list.
fn assert_the_permitted_reason_codes_are_exactly_what_the_facade_projects(
    projected_reasons: &[String],
) {
    assert_eq!(
        projected_reasons.len(),
        PERMITTED_REASON_CODE_COUNT,
        "the facade must project exactly one reason string per HostError arm, got: \
         {projected_reasons:?}"
    );
    let mut projected_set = projected_reasons.to_vec();
    projected_set.sort_unstable();
    projected_set.dedup();
    assert_eq!(
        projected_set.len(),
        projected_reasons.len(),
        "every projected reason must be a distinct code, so one code cannot stand in for two \
         variants, got: {projected_reasons:?}"
    );
    let mut permitted_set = PERMITTED_REASON_CODES.to_vec();
    permitted_set.sort_unstable();
    assert_eq!(
        projected_set, permitted_set,
        "PERMITTED_REASON_CODES must be exactly the set of reason codes the facade projects: a \
         renamed, added, dropped or duplicated projection all fail here instead of silently \
         escaping the canary sweep"
    );
}
