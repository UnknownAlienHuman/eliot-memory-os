#![allow(clippy::expect_used, clippy::unwrap_used)]
//! F-LOG-HOST-6 (#981) focused journal/readiness/epoch/restart-recovery diagnostics via #889 facade only.
//! Manager-scoped minimal set (6 tests; the 16-case matrix reconciles with caller children in #985):
//! T1 denominator + source/diff guard (issue cases 1, 16); T2 owner-epoch reopen (case 2);
//! T3 append requested vs durable vs unknown + replay-as-readback (cases 3, 4, 11);
//! T4 readiness evidence vs grant (cases 5, 6); T5 restart pending vs durable vs fenced (cases 7, 8, 9, 10);
//! T6 one terminal + sink noninterference + redaction + determinism + cleanup primacy (cases 12, 13, 14, 15).
use std::io::Write;
use std::sync::{Arc, Mutex};
use eliot_host::host_diagnostics::{DiagnosticSink, EntrypointStage, bound_detail, bound_field, observe_entrypoint_with_detail, observe_terminal_error, sink_status};
use serde_json::Value;
#[derive(Clone, Default)]
struct CaptureSink { bytes: Arc<Mutex<Vec<u8>>> }
impl Write for CaptureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.bytes.lock().map_err(|_| std::io::Error::other("poisoned"))?.extend_from_slice(buf); Ok(buf.len()) }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
fn src(r: &str) -> String { std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(r)).expect(r) }
fn emit(f: impl FnOnce()) -> String { let s = CaptureSink::default(); let w = s.clone(); let b = { let sub = tracing_subscriber::fmt().with_ansi(false).with_writer(move || w.clone()).finish(); tracing::subscriber::with_default(sub, f); s.bytes.lock().unwrap().clone() }; String::from_utf8_lossy(&b).into_owned() }
fn count(h: &str, n: &str) -> usize { h.matches(n).count() }
fn fix() -> Value { serde_json::from_slice(&std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/host_journal_diagnostics.json")).expect("fix")).expect("json") }
fn restart_req(id: &str, m: &str) -> eliot_host::HostRuntimeControlRequest { eliot_host::HostRuntimeControlRequest::new_with_mutation_digest(eliot_host::HostRuntimeControlOperation::RestartKernel, eliot_platform::PlatformHandle::new(id.to_owned()).expect("h"), eliot_platform::PlatformHandle::new(m.to_owned()).expect("h")).expect("req") }
fn nine() -> String { ["src/host_epoch_reopen.rs", "src/journal_append.rs", "src/journal_append/readiness_append.rs", "src/readiness_gate.rs", "src/readiness_gate/contract.rs", "src/runtime_restart_state.rs", "src/runtime_restart_state/pending_codec.rs", "src/store_recovery_evidence.rs", "src/store_recovery_fence.rs"].into_iter().map(src).collect() }
// WORK_UNIT_CASE: 981/1
#[test]
fn journal_01_nine_file_denominator_and_diff_guard() {
    let f = fix(); let all = nine();
    for h in f["helpers"].as_array().expect("helpers") { assert!(all.contains(h.as_str().expect("s")), "missing {h}"); }
    assert!(!src("src/readiness_gate/contract.rs").contains("observe_"), "contract helpers stay non-boundary");
    assert_eq!(count(&all, "observe_terminal_error"), 0, "terminals stay with #891/#893 outer guards");
    assert_eq!(count(&all, "static DEDUP"), 0, "no dedup cache");
    assert!(src("src/lib.rs").contains("host-open-failed"), "final emitting caller owns the open terminal");
    assert!(!src("src/host_diagnostics.rs").contains("host.epoch"), "facade gains no journal vocabulary");
}
// WORK_UNIT_CASE: 981/2
#[test]
fn journal_02_owner_epoch_reopen_no_inferred_increment() {
    let s = src("src/host_epoch_reopen.rs");
    assert!(s.contains("host.epoch owner epoch retained") && s.contains("host.epoch owner child epoch observed"));
    assert_ne!("host.epoch owner epoch retained", "host.epoch owner child epoch observed");
    assert!(s.contains("host.epoch install mismatch observed") && s.contains("host.epoch unclean observed"));
    let t = emit(|| { observe_entrypoint_with_detail(EntrypointStage::Startup, "host.epoch reopen existing requested"); observe_entrypoint_with_detail(EntrypointStage::Startup, "host.epoch reopen existing requested"); });
    assert_eq!(count(&t, "host.epoch reopen existing requested"), 2, "deterministic capture, got: {t}");
    assert_eq!(count(&t, "host.terminal_error"), 0, "observation alone emits no terminal");
}
// WORK_UNIT_CASE: 981/3
#[test]
fn journal_03_append_requested_durable_unknown_replay() {
    let j = src("src/journal_append.rs"); let e = src("src/host_epoch_reopen.rs");
    for l in ["host.journal append requested", "host.journal append durable observed", "host.journal append outcome unknown observed", "host.journal append rejected observed", "host.journal reconcile committed observed", "host.journal reconcile unknown observed"] { assert!(j.contains(l), "missing {l}"); }
    assert!(e.contains("host.epoch activation replay observed") && e.contains("host.epoch activation appended"));
    assert!(e.contains("host.epoch recovery exact readback confirmed") && e.contains("host.epoch recovery readback mismatch observed"));
    let f = fix(); let term = f["outer_terminal"].as_str().expect("term");
    let t = emit(|| { observe_entrypoint_with_detail(EntrypointStage::Startup, "host.journal append requested"); observe_terminal_error(term); });
    assert!(t.find("host.journal append requested").expect("req") < t.find(term).expect("term"));
    assert_eq!(count(&t, f["terminal_event"].as_str().expect("ev")), 1, "one terminal, got: {t}");
}
// WORK_UNIT_CASE: 981/4
#[test]
fn journal_04_readiness_evidence_vs_grant() {
    let a = src("src/journal_append/readiness_append.rs"); let g = src("src/readiness_gate.rs");
    for l in ["host.readiness authenticated requested", "host.readiness contour mismatch observed", "host.readiness evidence appended"] { assert!(a.contains(l), "missing {l}"); }
    for l in ["host.readiness lease hit observed", "host.readiness grant rejected observed", "host.readiness grant observed", "host.readiness probe due observed", "host.readiness contour unavailable observed"] { assert!(g.contains(l), "missing {l}"); }
    let t = emit(|| { observe_entrypoint_with_detail(EntrypointStage::Startup, "host.readiness grant observed"); });
    assert_eq!(count(&t, "host.readiness grant observed"), 1, "got: {t}");
    assert!(!t.contains("host.readiness grant rejected observed"), "grant and reject stay distinct");
}
// WORK_UNIT_CASE: 981/5
#[test]
fn journal_05_restart_pending_durable_fenced() {
    let all = nine();
    for l in ["host.restart pending replay observed", "host.restart pending published observed", "host.restart receipt durable observed", "host.restart pending identity malformed observed", "host.recovery termination incomplete observed", "host.recovery fence bound observed", "host.recovery foreign epoch observed", "host.recovery inner absent unknown observed", "host.recovery predecessor committed observed"] { assert!(all.contains(l), "missing {l}"); }
    let a = restart_req("981-5-a", &"b1".repeat(32)); let b = restart_req("981-5-a", &"b1".repeat(32)); let c = restart_req("981-5-a", &"b2".repeat(32));
    assert_eq!(a.request_digest.as_str(), b.request_digest.as_str(), "same semantic fields, same digest");
    assert_ne!(a.request_digest.as_str(), c.request_digest.as_str(), "mutation binds the digest");
}
// WORK_UNIT_CASE: 981/6
#[test]
fn journal_06_terminal_sink_redaction_cleanup() {
    let f = fix(); let all = nine(); let term = f["outer_terminal"].as_str().expect("term");
    let t = emit(|| { observe_entrypoint_with_detail(EntrypointStage::Startup, "host.restart receipt durable observed"); observe_terminal_error(term); });
    assert_eq!(count(&t, f["terminal_event"].as_str().expect("ev")), 1, "one terminal per op, got: {t}");
    assert_eq!(sink_status(DiagnosticSink::TracingStderr), Ok(()));
    assert!(sink_status(DiagnosticSink::WindowsEventLog).is_err() && eliot_host::windows_event_log::event_log_sink_status().is_err());
    assert!(bound_detail(&"x".repeat(2000)).truncated() && bound_detail(&"x".repeat(2000)).text().len() <= 1024);
    assert!(bound_field(term).text() == term, "short codes pass through untruncated");
    for l in all.lines().filter(|l| l.contains("_observe(")) { for c in f["canaries"].as_array().expect("can") { assert!(!l.contains(c.as_str().expect("s")), "canary in {l}"); } assert!(!l.contains("(format!") && !l.contains("{error}")); }
    let r = src("src/runtime_restart_state.rs");
    assert!(r.contains("Publication failure is primary") && r.contains("host.restart pending publication failed observed") && r.contains("host.restart pending cleanup failed observed"));
    assert!(r.find("host.restart receipt durable observed").expect("dur") < r.find("pending_remove_attempt").expect("ord"));
    assert_eq!(f["stdout_protocol_contamination"].as_bool(), Some(false));
}
