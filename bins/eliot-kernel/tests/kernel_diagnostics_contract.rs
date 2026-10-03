#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Focused contract tests for F-LOG-KERNEL-0 item 895 (Implements, not Closes).
//!
//! These tests prove only that the accepted observability owner's install
//! outcome is recorded once and answered singly and typed with no second
//! owner attempt, that the library-compiled facade performs no
//! process-global subscriber initialization of its own, the non-terminal
//! observability-install refusal, and one instrumented entrypoint
//! observation against the contract fixture in
//! `tests/data/kernel_diagnostics_contract.json`. They observe recorded owner
//! state and source text, never a live process-global subscriber, and they
//! do not assert the full 24-case matrix from the issue (complete
//! entrypoint/error/propagation
//! inventory, per-stage failure distinctions, sink-failure noninterference,
//! environment/frame canary sweeps, deterministic ordering, allowed-diff
//! review): those cases are deferred to the owning follow-ups and recorded
//! in the commit message. A log record is diagnostic evidence only, never
//! lifecycle authority, readiness, or completion.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_kernel::kernel_diagnostics::{
    DiagnosticSink, DiagnosticSubscriberOwner, EntrypointStage, KERNEL_DIAGNOSTICS_TARGET,
    KernelDiagnosticsError, MAX_DIAGNOSTIC_DETAIL_BYTES, MAX_DIAGNOSTIC_FIELD_BYTES,
    OBSERVABILITY_INSTALL_CONFIG_REFUSED, OBSERVABILITY_INSTALL_ENDPOINT_NOT_LOOPBACK,
    bound_detail, install_kernel_diagnostics, observe_entrypoint,
    observe_observability_install_refused, sink_status,
};
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

fn contract_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/kernel_diagnostics_contract.json");
    let bytes = std::fs::read(&path).expect("contract fixture must be readable");
    serde_json::from_slice(&bytes).expect("contract fixture must be valid JSON")
}

/// Runs one emission under a thread-local scoped subscriber and returns the
/// formatted bytes it produced.
///
/// The default dispatcher is thread-local, so this never reads or claims the
/// process-global subscriber and stays parallel-safe: the assertion is about
/// what the facade emits, not about who owns global dispatch.
fn capture_scoped_record(emit: impl FnOnce()) -> String {
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

// WORK_UNIT_CASE: 895/3
// WORK_UNIT_CASE: 895/4
#[test]
fn kernel_diagnostics_owner_install_outcome_is_recorded_once_and_event_log_is_absent() {
    // Before any accepted owner is recorded the facade has observed no global
    // dispatch, so stderr delivery must NOT be reported as available. A
    // constant `Ok(())` arm is self-fulfilling; this assertion is red the
    // moment the arm stops consulting the recorded owner state.
    let unowned = sink_status(DiagnosticSink::TracingStderr);
    assert!(
        unowned.is_err(),
        "no accepted owner has been recorded in this process, so tracing-stderr \
         delivery must be a typed error, got {unowned:?}"
    );

    // Ownership is decided by the accepted observability owner's real outcome,
    // never by a private latch: an install this process established succeeds.
    install_kernel_diagnostics(DiagnosticSubscriberOwner::Installed)
        .expect("the install that established the sole owner must succeed");

    // Only now may stderr delivery report available.
    assert_eq!(
        sink_status(DiagnosticSink::TracingStderr),
        Ok(()),
        "the recorded owner established global dispatch, so stderr delivery is available"
    );

    // A stand-by observer is bounded AlreadyOwned: it never installs a second
    // global subscriber, never panics, and never replaces the standing owner.
    let repeat = install_kernel_diagnostics(DiagnosticSubscriberOwner::AlreadyInstalled);
    assert_eq!(
        repeat,
        Err(KernelDiagnosticsError::AlreadyOwned),
        "a stand-by observer must be typed AlreadyOwned"
    );

    // A refused ownership claim leaves the standing owner's dispatch alone.
    assert_eq!(
        sink_status(DiagnosticSink::TracingStderr),
        Ok(()),
        "a refused stand-by install must not disturb the standing owner"
    );

    // The Windows Event Log sink is an explicitly absent seam (issue #984 still
    // open): typed Unavailable, never silent delivery elsewhere and never FFI.
    // (Partial 895/23.)
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(KernelDiagnosticsError::EventLogUnavailable)
    );

    // Truncation honesty: an oversized detail keeps a bounded prefix and
    // records its original length. (Supports 895/19 sizing.)
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
}

// WORK_UNIT_CASE: 895/3
#[test]
fn kernel_diagnostics_facade_installs_no_global_subscriber_of_its_own() {
    // #895's residual defect is a SECOND claim on the one process-global
    // subscriber: `eliot_observability_runtime::install` owns it, and the
    // facade may only record the accepted owner's outcome. No runtime
    // assertion in a parallel-safe test can observe that property (a test
    // that installed a global subscriber would be unparallel-safe and still
    // blind to the facade's own call), so this pins the source property on
    // the source text, the idiom already used by
    // `kernel_front_door_diagnostics.rs`. Reading the facade source is
    // compile-time-bound and installs nothing.
    let source = include_str!("../src/kernel_diagnostics.rs");
    // Every needle is assembled at compile time from literal fragments so
    // this assertion cannot match its own literal in the source it scans.
    for needle in [
        concat!("set_global_", "default"),
        concat!("try_", "init"),
        concat!("SetGlobalDefault", "Error"),
    ] {
        assert!(
            !source.contains(needle),
            "the diagnostics facade must perform no process-global subscriber \
             initialization of its own, but src/kernel_diagnostics.rs contains \
             {needle:?}"
        );
    }
}

// WORK_UNIT_CASE: 895/3
#[test]
fn kernel_observability_install_refusal_is_non_terminal_and_code_stable() {
    let fixture = contract_fixture();
    // Both event names are read from the contract fixture, so a renamed event is
    // red here rather than silently accepted by a restated literal.
    let terminal_event = fixture["terminal_event"]
        .as_str()
        .expect("fixture must pin the terminal event name");
    let refusal_event = fixture["observability_refusal_event"]
        .as_str()
        .expect("fixture must pin the observability refusal event name");
    let pinned_codes = fixture["observability_refusal_codes"]
        .as_object()
        .expect("fixture must pin the observability refusal codes");
    // The target is compared against the fixture's own pinned value, not
    // const-to-const: a renamed `KERNEL_DIAGNOSTICS_TARGET` is red here
    // instead of silently agreeing with a stale fixture key.
    let pinned_target = fixture["target"]
        .as_str()
        .expect("fixture must pin the facade target");
    assert_eq!(
        KERNEL_DIAGNOSTICS_TARGET, pinned_target,
        "the Rust facade target constant must agree with the pinned fixture target"
    );

    // Both fixed refusal variants map to distinct, stable, owner-issued codes.
    for code in [
        OBSERVABILITY_INSTALL_CONFIG_REFUSED,
        OBSERVABILITY_INSTALL_ENDPOINT_NOT_LOOPBACK,
    ] {
        // The emitted code is fixture-pinned vocabulary, never dynamic
        // `Display` prose of the underlying refusal.
        assert!(
            pinned_codes
                .values()
                .any(|pinned| pinned.as_str() == Some(code)),
            "fixture must pin the stable code {code} for a refused install"
        );

        let text = capture_scoped_record(|| observe_observability_install_refused(code));

        // The record carries the facade target and its own refusal event.
        assert!(
            text.contains(pinned_target),
            "refusal record must carry the fixture-pinned facade target \
             {pinned_target}, got: {text}"
        );
        assert!(
            text.contains(refusal_event),
            "refusal record must carry the refusal event {refusal_event}, got: {text}"
        );

        // The static code survives verbatim: codes are stable owner-issued
        // strings, never dynamic Display prose.
        assert!(
            text.contains(code),
            "refusal record must carry the static code {code}, got: {text}"
        );

        // A refused observability install is explicitly non-gating, so it must
        // never be inflated into the one process terminal record. This is the
        // assertion that turns red if the arm regresses to observe_terminal_error.
        assert!(
            !text.contains(terminal_event),
            "a non-gating install refusal must not emit the terminal event \
             {terminal_event}, got: {text}"
        );

        // Bounded output: one degraded observation must not produce an
        // unbounded operational surface.
        assert!(
            text.len() < 8 * 1024,
            "refusal capture must stay bounded, got {} bytes",
            text.len()
        );
    }

    // The two fixed refusals stay distinguishable: one code cannot stand in for
    // the other, so a collapsed mapping is red.
    assert_ne!(
        OBSERVABILITY_INSTALL_CONFIG_REFUSED, OBSERVABILITY_INSTALL_ENDPOINT_NOT_LOOPBACK,
        "each refused variant must keep its own stable code"
    );
}

// WORK_UNIT_CASE: 895/2
#[test]
fn kernel_diagnostics_entrypoint_observation_matches_contract_fixture() {
    // The facade is compiled once in the kernel library and observed here;
    // the binary's use is compile-gated in `src/main.rs` (same crate path,
    // no second `mod`/copy). Scoped capture shadows any global install, so
    // this test stays isolated and parallel-safe. (Case 895/2.)
    let fixture = contract_fixture();
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            observe_entrypoint(EntrypointStage::LaunchConfig);
        });
        sink.bytes.lock().unwrap().clone()
    };
    let text = String::from_utf8_lossy(&captured);

    // The observed record carries the facade target, the entrypoint event,
    // and the exact stage name pinned by the fixture.
    let expected_stage = fixture["stages"]["launch_config"]
        .as_str()
        .expect("fixture must pin the launch_config stage name");
    assert_eq!(
        EntrypointStage::LaunchConfig.as_str(),
        expected_stage,
        "facade stage name must match the contract fixture"
    );
    assert_eq!(
        EntrypointStage::Startup.as_str(),
        fixture["stages"]["startup"]
            .as_str()
            .expect("fixture must pin the startup stage name")
    );
    assert!(
        text.contains(KERNEL_DIAGNOSTICS_TARGET),
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
    // Bounded output: one observation must not produce an unbounded buffer.
    assert!(
        captured.len() < 8 * 1024,
        "diagnostic capture must stay bounded, got {} bytes",
        captured.len()
    );
}
