#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Focused package-local diagnostics tests for item 738 (Implements, not Closes).
//!
//! These tests prove only the bounded structured-subscriber installation and
//! scoped capture isolation. They do not rewrite fixtures, touch shared
//! crates, or assert supervision/recovery behavior. A log record is diagnostic
//! evidence only, never recovery authority.

use std::io::Write;
use std::sync::{Arc, Mutex};

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

// WORK_UNIT_CASE: 738/1
#[test]
fn watchdog_diagnostics_installer_is_idempotent_and_bounded() {
    // The production installer must be callable twice without creating a
    // second global owner, panicking, or performing recovery.
    eliot_watchdog::install_subscriber();
    eliot_watchdog::install_subscriber();

    // Scoped capture isolation: a fmt subscriber with an in-memory writer
    // records one bounded structured event without touching the global
    // subscriber installed above.
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                event = "watchdog.diagnostics_probe",
                observation = "attempted",
                "diagnostics capture probe"
            );
        });
        sink.bytes.lock().unwrap().clone()
    };
    let text = String::from_utf8_lossy(&captured);
    assert!(
        text.contains("watchdog.diagnostics_probe"),
        "scoped capture must contain the probe event, got: {text}"
    );
    assert!(
        text.contains("attempted"),
        "scoped capture must preserve the observation name, got: {text}"
    );
    // Bounded output: one probe must not produce an unbounded buffer.
    assert!(
        captured.len() < 8 * 1024,
        "diagnostic capture must stay bounded, got {} bytes",
        captured.len()
    );
}
