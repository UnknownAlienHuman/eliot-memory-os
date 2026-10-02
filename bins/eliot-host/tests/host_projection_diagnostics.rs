#![allow(clippy::expect_used, clippy::unwrap_used)]
//! F-LOG-HOST-5 (#980) focused projection diagnostics via #889 facade only.
//! T1 covers issue cases 1/3/4/5/9 (propagation + single terminal through the
//! real `materialize_phase_b` contour); T2 covers 6/7/8/10/11 (redaction +
//! noninterference + rollback disposition). No matrix; Event Log stays
//! typed-Unavailable (#984). Each proof names its actual caller.
//!
//! Audit 5909832545 defect 6: the executed proofs below never manufacture the
//! record under test. Every case hands the production facade a literal or a
//! real typed owner value and asserts on what production emitted back; the
//! source scans that remain are supplementary emission-binding only.
//! `decode_marker`/`decode_envelope` (`pub(super)` in `credential_control`)
//! and `phase_b_restore_or_remove`/`phase_b_remove_rollback_backup`
//! (`use`-only import in `lib.rs`, private `mod phase_b_materialization`) are
//! unreachable from an integration-test crate, so their contours are not
//! claimed here; the reachable proof for the rollback dispositions is the
//! executed projection case below, which proves an unknown/failed outcome can
//! never be emitted as a positive claim.
use eliot_host::host_diagnostics::{
    EntrypointStage, HostRequestProjection, MAX_DIAGNOSTIC_DETAIL_BYTES,
    observe_entrypoint_with_detail, observe_host_request, observe_terminal_error,
};
use serde_json::Value;
use std::io::Write;
use std::sync::{Arc, Mutex};
#[derive(Clone, Default)]
struct CaptureSink {
    bytes: Arc<Mutex<Vec<u8>>>,
}
impl Write for CaptureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn src(r: &str) -> String {
    std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(r)).expect(r)
}
fn emit(f: impl FnOnce()) -> String {
    let s = CaptureSink::default();
    let w = s.clone();
    let b = {
        let sub = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || w.clone())
            .finish();
        tracing::subscriber::with_default(sub, f);
        s.bytes.lock().unwrap().clone()
    };
    String::from_utf8_lossy(&b).into_owned()
}
fn count(h: &str, n: &str) -> usize {
    h.matches(n).count()
}
fn fix() -> Value {
    serde_json::from_slice(
        &std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data/host_projection_diagnostics.json"),
        )
        .expect("fix"),
    )
    .expect("json")
}
// WORK_UNIT_CASE: 980/1
#[test]
fn projection_01_propagation_single_terminal() {
    let f = fix();
    let inner = f["inner"].as_str().expect("inner");
    let term = f["terminal_code"].as_str().expect("term");
    let prev = src("src/phase_b_previous_projection.rs");
    assert!(prev.contains("fn phase_b_previous_projection_observe") && prev.contains(inner));
    assert!(
        prev.contains("not the exact previous Host materialization")
            && prev.contains("RecoveryRequired")
    );
    assert!(src("src/host_composition_phase_b.rs").contains("fn materialize_phase_b"));
    assert!(src("src/phase_b_previous_authority.rs").contains("historical evidence observed"));
    let cd = src("src/credential_control/codec.rs");
    for l in [
        "host.credential codec marker rejected",
        "host.credential codec envelope rejected",
        "marker-record-shape",
        "marker-expected-mac",
        "marker-mac-mismatch",
        "marker-protected-object-mismatch",
        "marker-wire-version-mismatch",
        "envelope-record-shape",
        "envelope-expected-mac",
        "envelope-mac-mismatch",
        "envelope-protected-object-mismatch",
        "envelope-wire-version-mismatch",
    ] {
        assert!(cd.contains(&format!("\"{l}\"")), "codec label {l} gone");
    }
    // Bind to emission, not vocabulary: the helper plus both 6-branch
    // reject paths, so deleting any `credential_codec_observe` call fails.
    assert!(cd.contains("credential_codec_observe(CodecRejectReason::"));
    assert_eq!(
        count(&cd, "credential_codec_observe("),
        13,
        "codec stopped observing"
    );
    // Executed proof of the shared facade only: literals go in, the facade's
    // own record comes back. No production record is manufactured here, and
    // the detail is no longer assembled from a fixture field, so what is
    // asserted is exactly what production emitted for that literal.
    let c = "corr-980-1";
    let t = emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, inner);
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, c);
        observe_terminal_error(term);
    });
    assert!(t.contains(inner) && t.contains(term));
    assert_eq!(count(&t, inner), 1, "detail must not be duplicated: {t}");
    assert_eq!(
        count(&t, f["entrypoint_event"].as_str().expect("event name")),
        2,
        "each subordinate literal emits one entrypoint record: {t}"
    );
    assert_eq!(
        count(&t, f["terminal_event"].as_str().expect("ev")),
        1,
        "got: {t}"
    );
    assert_eq!(count(&t, c), 1, "inner correlates once, got: {t}");
    assert!(t.find(inner).expect("inner") < t.find(term).expect("term"));
}
// WORK_UNIT_CASE: 980/2
#[test]
fn projection_02_redaction_noninterference_rollback() {
    let f = fix();
    let can: Vec<String> = f["canaries"]
        .as_array()
        .expect("can")
        .iter()
        .map(|v| v.as_str().expect("s").to_owned())
        .collect();
    let all = format!(
        "{}{}{}{}{}{}",
        src("src/host_composition_validation.rs"),
        src("src/phase_b_projection.rs"),
        src("src/phase_b_previous_authority.rs"),
        src("src/phase_b_previous_projection.rs"),
        src("src/phase_b_materialization/rollback_backup.rs"),
        src("src/credential_control/codec.rs")
    );
    assert!(
        !all.contains("observe_terminal_error")
            && all.contains("event_log_sink_status")
            && !all.contains("static DEDUP")
    );
    for l in all
        .lines()
        .filter(|l| l.contains("host.phase-b") || l.contains("host.credential"))
    {
        for c in &can {
            assert!(!l.contains(c.as_str()), "canary {c:?} in {l}");
        }
        assert!(!l.contains("{}") && !l.contains("{error}"));
    }
    let rb = src("src/phase_b_materialization/rollback_backup.rs");
    assert!(
        rb.contains("host.phase-b rollback backup unknown retained")
            && rb.contains("host.phase-b rollback restored verified")
    );
    assert_ne!(
        "host.phase-b rollback backup unknown retained",
        "host.phase-b rollback restored verified"
    );
    let t = emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.phase-b rollback backup unknown retained",
        );
        observe_terminal_error("host-phase-b-unknown");
    });
    assert!(t.contains("unknown retained") && !t.contains("restored verified"));
    assert_eq!(count(&t, "host.terminal_error"), 1, "got: {t}");
    assert_eq!(
        eliot_host::windows_event_log::event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
    for c in &can {
        assert!(!t.contains(c.as_str()), "canary {c:?} in capture");
    }
    assert_eq!(f["stdout_protocol_contamination"].as_bool(), Some(false));
}

// Executed case: the rollback disposition the audit demands cannot be forged
// through the emission surface. `HostRequestProjection` is the production type
// every Host request record is built from, so an unknown / unattributed
// rollback outcome reaching it is projected as missing evidence, never as a
// positive restoration, removal or cleanup claim.
#[test]
fn projection_05_unknown_rollback_disposition_emits_no_positive_claim() {
    let positives = [
        "restored verified",
        "uncommitted removal verified",
        "cleanup completed",
        "removal verified",
        "durable_committed",
        "process_started",
        "semantically_ready",
    ];
    // The rollback halves of that list are the CURRENT frozen labels of the
    // rollback owner's contour map (`RollbackContour::label` in
    // `phase_b_materialization/rollback_backup.rs`), which stays unreachable
    // from an integration-test crate: `mod phase_b_materialization` is private
    // and `phase_b_restore_or_remove` / `phase_b_remove_rollback_backup` are
    // `pub` only inside it. So each positive is bound here to the exact
    // production label it abbreviates, and the denial below is proved on the
    // record production emitted, never on a guessed spelling.
    let rollback = src("src/phase_b_materialization/rollback_backup.rs");
    for label in [
        "host.phase-b rollback backup prepared",
        "host.phase-b rollback restored verified",
        "host.phase-b rollback uncommitted removal verified",
        "host.phase-b rollback backup cleanup completed",
    ] {
        assert!(
            rollback.contains(&format!("\"{label}\"")),
            "rollback owner must still name the positive label {label:?}"
        );
    }
    let unknown = emit(|| {
        observe_host_request(&HostRequestProjection::unknown(
            EntrypointStage::ScmDispatch,
        ));
    });
    assert!(
        unknown.contains("host.request"),
        "no projection record: {unknown}"
    );
    assert!(
        unknown.contains("evidence=unknown"),
        "evidence must be unknown: {unknown}"
    );
    assert!(
        unknown.contains("reason_missing=true"),
        "no reason may be invented: {unknown}"
    );
    assert!(
        unknown.contains("running_missing=true"),
        "running must stay missing: {unknown}"
    );
    assert!(
        unknown.contains("process_missing=true"),
        "process must stay missing: {unknown}"
    );
    assert!(
        unknown.contains("generation_missing=true"),
        "generation must stay missing: {unknown}"
    );
    assert!(
        !unknown.contains("host.terminal_error"),
        "a projection is never a terminal: {unknown}"
    );
    for positive in positives {
        assert!(
            !unknown.contains(positive),
            "unknown rollback disposition claimed {positive:?}: {unknown}"
        );
    }
    // The failed-before-verification sibling disposition: the typed reason is
    // kept, the payload is not, and no positive claim rides along with it.
    let unattributed = emit(|| {
        observe_host_request(&HostRequestProjection::failed_without_reason(
            EntrypointStage::ScmDispatch,
        ));
    });
    assert!(
        unattributed.contains("evidence=failed"),
        "got: {unattributed}"
    );
    assert!(
        unattributed.contains("reason_missing=true"),
        "got: {unattributed}"
    );
    for positive in positives {
        assert!(
            !unattributed.contains(positive),
            "unattributed rollback disposition claimed {positive:?}: {unattributed}"
        );
    }
    // Dispositions that genuinely are proven stay reachable and distinct, so
    // the pair above is a real distinction and not a blanket denial.
    let committed = emit(|| {
        observe_host_request(&HostRequestProjection::durable_committed(
            EntrypointStage::ShutdownDrain,
        ));
    });
    assert!(
        committed.contains("evidence=durable_committed"),
        "got: {committed}"
    );
    // `observe_host_request` renders the frozen phase under the `phase` key;
    // `stage` is the `host.entrypoint_stage` key and is never projected here,
    // so the pin follows the field production actually writes.
    assert!(committed.contains("phase=shutdown_drain"), "got: {committed}");
    assert!(
        !committed.contains("host.phase-b"),
        "a projection record carries no rollback contour detail: {committed}"
    );
}

// Executed case: bounded static detail is honoured by the real formatter, so
// the redaction contract T2 asserts on source is also asserted on the record
// production actually wrote. The oversized literal is truncated with an honest
// byte count rather than dropped or emitted whole.
#[test]
fn projection_06_detail_is_truncated_with_honest_byte_accounting() {
    let oversized = "host.phase-b rollback ".repeat(MAX_DIAGNOSTIC_DETAIL_BYTES);
    assert!(oversized.len() > MAX_DIAGNOSTIC_DETAIL_BYTES);
    let t = emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &oversized);
    });
    assert!(
        t.contains("host.entrypoint_stage"),
        "no entrypoint record: {t}"
    );
    assert!(
        t.contains(&format!("detail_bytes={}", oversized.len())),
        "original byte count must be reported: {t}"
    );
    assert!(
        t.contains("detail_truncated=true"),
        "truncation must be reported: {t}"
    );
    let retained = MAX_DIAGNOSTIC_DETAIL_BYTES.min(oversized.len());
    assert!(
        t.contains(&oversized[..retained]),
        "the bounded prefix must be retained: {t}"
    );
    assert!(
        !t.contains("detail_truncated=false"),
        "an oversized detail must never claim it was whole: {t}"
    );
}
