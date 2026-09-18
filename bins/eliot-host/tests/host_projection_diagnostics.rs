#![allow(clippy::expect_used, clippy::unwrap_used)]
//! F-LOG-HOST-5 (#980) focused projection diagnostics via #889 facade only.
//! T1 covers issue cases 1/3/4/5/9 (propagation + single terminal through the
//! real `materialize_phase_b` contour); T2 covers 6/7/8/10/11 (redaction +
//! noninterference + rollback disposition). No matrix; Event Log stays
//! typed-Unavailable (#984). Each proof names its actual caller.
use std::io::Write;
use std::sync::{Arc, Mutex};
use eliot_host::host_diagnostics::{EntrypointStage, observe_entrypoint_with_detail, observe_terminal_error};
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
fn fix() -> Value { serde_json::from_slice(&std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/host_projection_diagnostics.json")).expect("fix")).expect("json") }
// WORK_UNIT_CASE: 980/1
#[test]
fn projection_01_propagation_single_terminal() {
    let f = fix(); let inner = f["inner"].as_str().expect("inner"); let term = f["terminal_code"].as_str().expect("term");
    let prev = src("src/phase_b_previous_projection.rs");
    assert!(prev.contains("fn phase_b_previous_projection_observe") && prev.contains(inner));
    assert!(prev.contains("not the exact previous Host materialization") && prev.contains("RecoveryRequired"));
    assert!(src("src/host_composition_phase_b.rs").contains("fn materialize_phase_b"));
    assert!(src("src/phase_b_previous_authority.rs").contains("historical evidence observed"));
    assert!(src("src/credential_control/codec.rs").contains("malformed retained"));
    let c = "corr-980-1";
    let t = emit(|| { observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &format!("{inner} {c}")); observe_terminal_error(term); });
    assert!(t.contains(inner) && t.contains(term));
    assert_eq!(count(&t, f["terminal_event"].as_str().expect("ev")), 1, "got: {t}");
    assert_eq!(count(&t, c), 1, "inner correlates once, got: {t}");
    assert!(t.find(inner).expect("inner") < t.find(term).expect("term"));
}
// WORK_UNIT_CASE: 980/2
#[test]
fn projection_02_redaction_noninterference_rollback() {
    let f = fix(); let can: Vec<String> = f["canaries"].as_array().expect("can").iter().map(|v| v.as_str().expect("s").to_owned()).collect();
    let all = format!("{}{}{}{}{}{}", src("src/host_composition_validation.rs"), src("src/phase_b_projection.rs"), src("src/phase_b_previous_authority.rs"), src("src/phase_b_previous_projection.rs"), src("src/phase_b_materialization/rollback_backup.rs"), src("src/credential_control/codec.rs"));
    assert!(!all.contains("observe_terminal_error") && all.contains("event_log_sink_status") && !all.contains("static DEDUP"));
    for l in all.lines().filter(|l| l.contains("host.phase-b") || l.contains("host.credential")) { for c in &can { assert!(!l.contains(c.as_str()), "canary {c:?} in {l}"); } assert!(!l.contains("{}") && !l.contains("{error}")); }
    let rb = src("src/phase_b_materialization/rollback_backup.rs");
    assert!(rb.contains("host.phase-b rollback backup unknown retained") && rb.contains("host.phase-b rollback restored verified"));
    assert_ne!("host.phase-b rollback backup unknown retained", "host.phase-b rollback restored verified");
    let t = emit(|| { observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, "host.phase-b rollback backup unknown retained"); observe_terminal_error("host-phase-b-unknown"); });
    assert!(t.contains("unknown retained") && !t.contains("restored verified"));
    assert_eq!(count(&t, "host.terminal_error"), 1, "got: {t}");
    assert_eq!(eliot_host::windows_event_log::event_log_sink_status(), Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable));
    for c in &can { assert!(!t.contains(c.as_str()), "canary {c:?} in capture"); }
    assert_eq!(f["stdout_protocol_contamination"].as_bool(), Some(false));
}
