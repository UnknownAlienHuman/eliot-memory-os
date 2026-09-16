#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Kernel generation/control diagnostics (F-LOG-KERNEL-4, issue #903).
//!
//! Single focused integrator proof that this leaf's observations flow through
//! the #895 `kernel_diagnostics` facade. Each leg drives a real production
//! callsite through its existing public seam and pins its boundary against
//! `tests/data/kernel_generation_control_diagnostics.json`:
//! leg 1 reads the generation-route snapshot (attempt/success, no terminal);
//! leg 2 applies the `ProbeReady` control command, which is deterministically
//! rejected with `ReadinessNotProven` and its stable `CONTROL_*` terminal;
//! leg 3 applies an uncommitted generation cutover, which is deterministically
//! rejected, fences the gateway, and emits its stable `CUTOVER_*` terminal.
//! Diagnostics only: behavior (return values, fencing) is asserted unchanged.
//!
//! Deferred broader matrix (for the PR body, not this file): daemon-runtime
//! recovery terminals, snapshot/cutover per-variant terminal-code sweeps,
//! recovery persist/replay phase inventory, identity/health omission outcomes,
//! secret-canary sweeps beyond the inline slice proofs, deterministic ordering
//! proofs, and multi-composition interference checks.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
use eliot_kernel::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET;
use eliot_kernel::{KernelComposition, KernelConfig};
use eliot_kernel_core::{CutoverDecision, RouteScope};
use eliot_kernel_service::{KernelControlCommand, KernelServiceError};
use eliot_runtime_contracts::GenerationCutoverState;
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

fn fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/kernel_generation_control_diagnostics.json");
    let bytes = std::fs::read(&path).expect("generation/control fixture must be readable");
    serde_json::from_slice(&bytes).expect("generation/control fixture must be valid JSON")
}

fn fixture_str(fixture: &Value, pointer: &str) -> String {
    fixture
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("fixture must pin {pointer}"))
        .to_owned()
}

fn capture_with<F, R>(f: F) -> (String, R)
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

struct TempGuard {
    root: std::path::PathBuf,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn test_kernel() -> (KernelComposition, TempGuard) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!("eliot-903-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    (kernel, TempGuard { root })
}

/// An uncommitted cutover decision: structurally valid (distinct generations,
/// strictly rising epoch) but never `Committed`, so the gateway rejects it
/// before any ORS staging and fences with a `Platform` terminal.
fn uncommitted_cutover() -> CutoverDecision {
    CutoverDecision::new(
        "eliot-903-integrator-cutover",
        RouteScope::new("daemon").expect("daemon scope"),
        Some(ResourceGeneration::new(1).expect("old generation")),
        ResourceGeneration::new(2).expect("new generation"),
        AuthorityEpoch::new(1).expect("old epoch"),
        AuthorityEpoch::new(2).expect("new epoch"),
        GenerationCutoverState::Preparing,
    )
    .expect("uncommitted cutover decision")
}

#[test]
fn kernel_generation_control_observations_flow_through_diagnostics_facade() {
    let fixture = fixture();
    let (kernel, _guard) = test_kernel();
    let terminal_event = fixture_str(&fixture, "/terminal_event");

    // Leg 1 (generation snapshot): a successful route read emits its
    // attempt/success pair through the facade with no terminal record.
    let snapshot_requested = fixture_str(&fixture, "/generation/snapshot_requested");
    let snapshot_committed = fixture_str(&fixture, "/generation/snapshot_committed");
    let (text, snapshot) = capture_with(|| kernel.generation_route_snapshot());
    snapshot.expect("snapshot read on a fresh composition must succeed");
    assert!(
        text.contains(KERNEL_DIAGNOSTICS_TARGET),
        "snapshot capture must contain the facade target, got: {text}"
    );
    for marker in [&snapshot_requested, &snapshot_committed] {
        assert!(
            text.contains(marker),
            "missing generation marker {marker}, got: {text}"
        );
    }
    assert!(
        !text.contains(&terminal_event),
        "successful snapshot must not emit a terminal record, got: {text}"
    );

    // Leg 2 (control terminal stability): `ProbeReady` cannot carry a
    // caller-shaped receipt, so the transition gateway deterministically
    // rejects it; exactly one stable terminal code flows through the facade
    // and the typed error is preserved.
    let transition_requested = fixture_str(&fixture, "/control/transition_requested");
    let transition_failed = fixture_str(&fixture, "/control/transition_failed");
    let probe_terminal = fixture_str(&fixture, "/control/probe_ready_terminal");
    let (text, outcome) = capture_with(|| kernel.apply_control(KernelControlCommand::ProbeReady));
    assert!(
        matches!(outcome, Err(KernelServiceError::ReadinessNotProven)),
        "ProbeReady must stay rejected as ReadinessNotProven, got: {outcome:?}"
    );
    assert!(
        text.contains(KERNEL_DIAGNOSTICS_TARGET),
        "control capture must contain the facade target, got: {text}"
    );
    for marker in [
        &transition_requested,
        &transition_failed,
        &terminal_event,
        &probe_terminal,
    ] {
        assert!(
            text.contains(marker),
            "missing control marker {marker}, got: {text}"
        );
    }

    // Leg 3 (generation-cutover marker + terminal): the uncommitted decision
    // is rejected by the cutover gateway, which fences and emits its single
    // stable terminal; the gateway stays fenced afterwards.
    let cutover_requested = fixture_str(&fixture, "/generation/cutover_requested");
    let cutover_failed = fixture_str(&fixture, "/generation/cutover_failed");
    let cutover_terminal = fixture_str(&fixture, "/generation/cutover_uncommitted_terminal");
    let (text, outcome) = capture_with(|| kernel.apply_generation_cutover(&uncommitted_cutover()));
    assert!(
        outcome.is_err(),
        "uncommitted cutover must stay rejected, got: {outcome:?}"
    );
    assert!(
        text.contains(KERNEL_DIAGNOSTICS_TARGET),
        "cutover capture must contain the facade target, got: {text}"
    );
    for marker in [
        &cutover_requested,
        &cutover_failed,
        &terminal_event,
        &cutover_terminal,
    ] {
        assert!(
            text.contains(marker),
            "missing cutover marker {marker}, got: {text}"
        );
    }
    assert!(
        kernel.generation_route_snapshot().is_err(),
        "rejected cutover must leave the generation gateway fenced"
    );

    // Bounded output: three observed operations must not produce unbounded buffers.
    assert!(
        text.len() < 8 * 1024,
        "diagnostic capture must stay bounded, got {} bytes",
        text.len()
    );
}
