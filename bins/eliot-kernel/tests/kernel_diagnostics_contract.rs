#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Focused contract tests for F-LOG-KERNEL-0 item 895 (Implements, not Closes).
//!
//! These tests prove only the library-compiled facade installation and one
//! instrumented entrypoint observation against the contract fixture in
//! `tests/data/kernel_diagnostics_contract.json`. They do not assert the
//! full 24-case matrix from the issue (complete entrypoint/error/propagation
//! inventory, per-stage failure distinctions, sink-failure noninterference,
//! environment/frame canary sweeps, deterministic ordering, allowed-diff
//! review): those cases are deferred to the owning follow-ups and recorded
//! in the commit message. A log record is diagnostic evidence only, never
//! lifecycle authority, readiness, or completion.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_kernel::kernel_diagnostics::{
    DiagnosticSink, EntrypointStage, KERNEL_DIAGNOSTICS_TARGET, MAX_DIAGNOSTIC_DETAIL_BYTES,
    MAX_DIAGNOSTIC_FIELD_BYTES, bound_detail, install_kernel_diagnostics, observe_entrypoint,
    sink_status,
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

// WORK_UNIT_CASE: 895/3
// WORK_UNIT_CASE: 895/4
#[test]
fn kernel_diagnostics_install_is_singly_owned_and_event_log_is_absent() {
    // First installation claims process ownership; a repeat install is
    // bounded AlreadyOwned, never a panic, a replacement, or a second owner.
    // (Cases 895/3 first install, 895/4 duplicate init.)
    install_kernel_diagnostics().expect("first facade install must succeed");
    let repeat = install_kernel_diagnostics();
    assert_eq!(
        repeat,
        Err(eliot_kernel::kernel_diagnostics::KernelDiagnosticsError::AlreadyOwned),
        "repeat install must be typed AlreadyOwned"
    );

    // Tracing-stderr delivery is available; the Windows Event Log sink is an
    // explicitly absent seam (issue #984 still open): typed Unavailable,
    // never silent delivery elsewhere and never FFI. (Partial 895/23.)
    assert_eq!(sink_status(DiagnosticSink::TracingStderr), Ok(()));
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(eliot_kernel::kernel_diagnostics::KernelDiagnosticsError::EventLogUnavailable)
    );

    // Truncation honesty: an oversized detail keeps a bounded prefix and
    // records its original length. (Supports 895/19 sizing.)
    let oversized = "x".repeat(8 * MAX_DIAGNOSTIC_DETAIL_BYTES);
    let bounded = bound_detail(&oversized);
    assert_eq!(bounded.original_bytes(), oversized.len());
    assert!(bounded.truncated(), "oversized input must report truncation");
    assert!(
        bounded.text().len() <= MAX_DIAGNOSTIC_DETAIL_BYTES,
        "retained prefix must stay bounded, got {} bytes",
        bounded.text().len()
    );
    let exact = "y".repeat(MAX_DIAGNOSTIC_DETAIL_BYTES);
    let kept = bound_detail(&exact);
    assert!(!kept.truncated(), "in-bound input must not report truncation");
    assert_eq!(kept.text(), exact);
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
