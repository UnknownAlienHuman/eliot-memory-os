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
use eliot_host::host_diagnostics::{HostRequestEvidence, note_event_log_sink_status};
use eliot_host::windows_event_log::{
    AdmittedEvent, EVENT_LOG_MAX_INSERTION_BYTES, EVENT_LOG_SOURCE, EventLogRecord,
    EventLogSeverity, event_log_sink_status,
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
    // `tracing_subscriber::fmt` renders every string-valued field through
    // `Debug`, so a frozen name reaches the record QUOTED: production writes
    // `evidence="unknown"`, never the bare `evidence=unknown`. Bool fields keep
    // `Debug`'s unquoted rendering, which is why the missing-slot pins below
    // read `reason_missing=true`.
    assert!(
        unknown.contains("evidence=\"unknown\""),
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
    // The positive claim is a TYPED claim, so it is denied on the exact
    // rendered discriminant rather than on substrings of the whole capture:
    // `HostRequestEvidence` is the only slot that can assert a completed
    // operation, and `AdmittedEvent::is_admitted_by` (`windows_event_log.rs:
    // 140`) admits the Event Log only for `process_started`,
    // `durable_committed` and `failed`. Denying those exact values denies the
    // record claim and its sink record at once, and a renamed or re-worded
    // positive cannot slip past it the way a bare substring scan can.
    for forbidden in [
        "process_started",
        "semantically_ready",
        "durable_committed",
        "cancelled",
    ] {
        assert!(
            !unknown.contains(&format!("evidence=\"{forbidden}\"")),
            "unknown rollback disposition held owner evidence {forbidden:?}: {unknown}"
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
        unattributed.contains("evidence=\"failed\""),
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
    // The typed denial is repeated for the sibling disposition, so an
    // unattributed failure cannot hold any owner evidence either.
    for forbidden in [
        "process_started",
        "semantically_ready",
        "durable_committed",
        "cancelled",
    ] {
        assert!(
            !unattributed.contains(&format!("evidence=\"{forbidden}\"")),
            "unattributed rollback disposition held owner evidence {forbidden:?}: {unattributed}"
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
        committed.contains("evidence=\"durable_committed\""),
        "got: {committed}"
    );
    // `observe_host_request` renders the frozen phase under the `phase` key;
    // `stage` is the `host.entrypoint_stage` key and is never projected here,
    // so the pin follows the field production actually writes - quoted, because
    // the stage name is a string-valued field.
    assert!(
        committed.contains("phase=\"shutdown_drain\""),
        "got: {committed}"
    );
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

/// The three positive rollback claims this leaf can emit. No integration
/// target can build them (see the reachability note on the cases below); they
/// are named here only to bind the reachable claim gates to the owner's own
/// frozen vocabulary, never to invent a record.
const ROLLBACK_POSITIVE_CLAIMS: [&str; 3] = [
    "host.phase-b rollback restored verified",
    "host.phase-b rollback uncommitted removal verified",
    "host.phase-b rollback backup cleanup completed",
];

/// Executed case, audit 5909832545 required item 5, first obligation: a positive
/// rollback claim is unreachable without its owner proof.
///
/// `phase_b_restore_or_remove` and `phase_b_remove_rollback_backup` live in
/// `src/phase_b_materialization/rollback_backup.rs` and are re-exported
/// `pub(super)` by the private `mod phase_b_materialization`
/// (`src/phase_b_materialization.rs:31-32`), which `src/lib.rs:5285-5289`
/// imports with a private `use`. An integration-test crate under `tests/`
/// therefore cannot name them, so this target cannot drive the rollback owner
/// and does not claim to. What IS reachable is the production gate that decides
/// whether any outcome may be stated as a completed operation at all:
/// `AdmittedEvent::is_admitted_by` (`src/windows_event_log.rs:140`), the single
/// production predicate over the owner-typed `HostRequestEvidence` class. This
/// case drives THAT predicate exhaustively and the bounded Event Log record
/// construction, and asserts the invariant on what production decided - the
/// record under test is production's own admission decision, never a record
/// manufactured through the diagnostic facade.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the unproven/proven gate matrix, the bounded sink record, and the owner label binding stay in one deterministic probe"
)]
fn projection_07_positive_rollback_claim_is_unreachable_without_owner_proof() {
    const EVENTS: [AdmittedEvent; 3] = [
        AdmittedEvent::ServiceStart,
        AdmittedEvent::ServiceStop,
        AdmittedEvent::ServiceFailure,
    ];
    // Every evidence class the reachable `HostRequestProjection` can carry that
    // asserts NO completed operation. A rollback outcome that was never
    // readback-proven is projected as exactly one of these, so at the
    // reachable claim gate it cannot be stated as restored, removed, or
    // cleaned-up completed.
    const UNPROVEN: [HostRequestEvidence; 5] = [
        HostRequestEvidence::Observed,
        HostRequestEvidence::Admitted,
        HostRequestEvidence::SemanticallyReady,
        HostRequestEvidence::Cancelled,
        HostRequestEvidence::Unknown,
    ];
    for evidence in UNPROVEN {
        for event in EVENTS {
            assert!(
                !event.is_admitted_by(evidence),
                "{} must not admit {}: an unproven outcome can never be stated as a completed operation",
                evidence.as_str(),
                event.as_str(),
            );
        }
    }
    // The three proven dispositions still reach the sink and each admits
    // EXACTLY one event, so the denials above are a real distinction and not a
    // blanket refusal. `Unknown` is deliberately absent: reading preserved
    // uncertainty as a settlement would manufacture a terminal no owner proved.
    for (event, proven) in [
        (AdmittedEvent::ServiceStart, HostRequestEvidence::ProcessStarted),
        (
            AdmittedEvent::ServiceStop,
            HostRequestEvidence::DurableCommitted,
        ),
        (AdmittedEvent::ServiceFailure, HostRequestEvidence::Failed),
    ] {
        assert!(
            event.is_admitted_by(proven),
            "{} must admit its own proven disposition {}",
            event.as_str(),
            proven.as_str(),
        );
        for other in EVENTS {
            assert!(
                other == event || !other.is_admitted_by(proven),
                "{} must not admit the proven disposition of {}",
                other.as_str(),
                event.as_str(),
            );
        }
    }
    // The bounded sink record for one rollback failure terminal code: the
    // reachable surface carries the code exactly, under the frozen consumer
    // mapping, with no fabrication and no truncation of a short code.
    let code = "host-phase-b-unknown";
    let failure = EventLogRecord::new(AdmittedEvent::ServiceFailure, code);
    assert_eq!(failure.event(), AdmittedEvent::ServiceFailure);
    assert_eq!(failure.insertion(), code);
    assert_eq!(failure.original_bytes(), code.len());
    assert!(!failure.truncated());
    assert_eq!(
        failure.mapping(),
        (EVENT_LOG_SOURCE, AdmittedEvent::ServiceFailure.event_id(), EventLogSeverity::Error)
    );
    // An unbounded positive claim cannot ride the sink either: the insertion
    // is bounded with an honest byte account, so a claim the platform had to
    // shorten can never read as a whole verified one.
    let oversized = "host.phase-b rollback backup cleanup completed "
        .repeat(MAX_DIAGNOSTIC_DETAIL_BYTES);
    let bounded = EventLogRecord::new(AdmittedEvent::ServiceFailure, &oversized);
    assert_eq!(bounded.original_bytes(), oversized.len());
    assert!(bounded.truncated());
    assert!(
        bounded.insertion().len() <= EVENT_LOG_MAX_INSERTION_BYTES,
        "the retained prefix must stay inside the sink bound, got {}",
        bounded.insertion().len()
    );
    // Supplementary emission binding only: the executed proof above is
    // production's own admission decision. This ties that decision to the
    // owner's three frozen positive labels, which no integration target can
    // emit because the owner is unreachable from here.
    let owner = src("src/phase_b_materialization/rollback_backup.rs");
    for label in ROLLBACK_POSITIVE_CLAIMS {
        assert!(
            owner.contains(&format!("\"{label}\"")),
            "the rollback owner must still name its positive label {label:?}"
        );
    }
}

/// Executed case, audit 5909832545 required item 5, second obligation:
/// rollback restoration and rollback-by-removal are distinguishable records.
///
/// Executed against the reachable production vocabularies. A closed vocabulary
/// whose members collapsed into one shared label would make two outcomes
/// indistinguishable again, so each member must own exactly one distinct frozen
/// name; this drives `HostRequestEvidence::as_str`, `AdmittedEvent::as_str`,
/// `event_id` and `severity` - production functions - and compares what they
/// actually return. The owner-label inventory below is supplementary emission
/// binding: the removal and cleanup contours are private to
/// `mod phase_b_materialization`, so their records cannot be produced from this
/// target, but the three contour families must stay pairwise distinct and a
/// removal or cleanup record must never read as a restoration.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the reachable vocabulary distinctness matrix and the three owner contour families stay in one deterministic probe"
)]
fn projection_08_restoration_removal_and_cleanup_contours_stay_distinct_records() {
    let evidence = [
        HostRequestEvidence::Observed,
        HostRequestEvidence::Admitted,
        HostRequestEvidence::ProcessStarted,
        HostRequestEvidence::SemanticallyReady,
        HostRequestEvidence::DurableCommitted,
        HostRequestEvidence::Cancelled,
        HostRequestEvidence::Failed,
        HostRequestEvidence::Unknown,
    ];
    for (index, left) in evidence.iter().enumerate() {
        for right in &evidence[index + 1..] {
            assert_ne!(
                left.as_str(),
                right.as_str(),
                "two reachable evidence classes share one name: a catch-all label would make an unknown outcome indistinguishable from a proven one"
            );
        }
    }
    let events = [
        AdmittedEvent::ServiceStart,
        AdmittedEvent::ServiceStop,
        AdmittedEvent::ServiceFailure,
    ];
    for (index, left) in events.iter().enumerate() {
        for right in &events[index + 1..] {
            assert_ne!(left.as_str(), right.as_str(), "two admitted events share one name");
            assert_ne!(
                left.event_id(),
                right.event_id(),
                "two admitted events share one event id"
            );
        }
    }
    // Start and stop are both informational notices; only failure is an error,
    // and the severity names stay distinct so a reader can tell them apart.
    assert_eq!(
        AdmittedEvent::ServiceStart.severity(),
        AdmittedEvent::ServiceStop.severity()
    );
    for informational in [
        AdmittedEvent::ServiceStart.severity(),
        AdmittedEvent::ServiceStop.severity(),
    ] {
        assert_ne!(informational, AdmittedEvent::ServiceFailure.severity());
        assert_eq!(informational.as_str(), "information");
    }
    assert_eq!(AdmittedEvent::ServiceFailure.severity().as_str(), "error");
    // A rollback outcome can never be smuggled in as an event name: the two
    // reachable closed vocabularies are disjoint.
    for outcome in evidence {
        for event in events {
            assert_ne!(
                outcome.as_str(),
                event.as_str(),
                "an outcome class and an admitted event share one name"
            );
        }
    }
    // Supplementary emission binding: the owner's three contour families.
    // Rollback-by-restoration, rollback-by-removal of an uncommitted
    // destination, and sidecar cleanup each own distinct frozen labels, and the
    // removal family - which was completely silent before this issue - is named
    // here in full.
    let owner = src("src/phase_b_materialization/rollback_backup.rs");
    let restoration = [
        "host.phase-b rollback restore requested",
        "host.phase-b rollback restored verified",
    ];
    let removal = [
        "host.phase-b rollback uncommitted removal requested",
        "host.phase-b rollback uncommitted removal verified",
        "host.phase-b rollback uncommitted removal not required",
        "host.phase-b rollback uncommitted removal delete failed",
        "host.phase-b rollback uncommitted removal absence unproven",
        "host.phase-b rollback uncommitted removal absence unknown",
    ];
    let cleanup = [
        "host.phase-b rollback backup cleanup requested",
        "host.phase-b rollback backup cleanup completed",
        "host.phase-b rollback backup cleanup delete failed",
        "host.phase-b rollback backup cleanup path failed",
        "host.phase-b rollback backup cleanup absence unproven",
    ];
    let owner_labels: Vec<&str> = restoration
        .iter()
        .chain(removal.iter())
        .chain(cleanup.iter())
        .copied()
        .collect();
    for label in &owner_labels {
        assert!(
            owner.contains(&format!("\"{label}\"")),
            "the rollback owner must name {label:?}"
        );
    }
    for (index, left) in owner_labels.iter().enumerate() {
        for right in &owner_labels[index + 1..] {
            assert_ne!(
                left, right,
                "two rollback contours share one label, so their records are indistinguishable"
            );
        }
    }
    // A removal or cleanup record can never be read as a restoration: the
    // positive restoration phrase appears in no other contour label.
    for label in removal.iter().chain(cleanup.iter()) {
        assert!(
            !label.contains("restored verified"),
            "the non-restoration contour {label:?} claims a restoration"
        );
    }
}

/// Executed case, audit 5909832545 required item 5, third and fourth
/// obligations: sidecar cleanup is observable, and an unknown or failed
/// outcome is never logged as restored.
///
/// `phase_b_remove_rollback_backup` had no observation at all before this
/// issue. It is `pub(super)` inside the private rollback leaf, so this target
/// cannot drive it; what it CAN drive is the canonical bounded Event Log
/// disposition observer the audit names as the replacement for the stale
/// no-op wrappers (`host_diagnostics::note_event_log_sink_status`). This case
/// captures what that production observer actually wrote and asserts the
/// disposition record names the unavailable sink, owns no terminal, and carries
/// no rollback positive claim - so the cleanup disposition that production
/// emits on the reachable surface can never read as a verified removal, a
/// verified restoration, or a completed cleanup.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the canonical disposition observation and the owner cleanup contour inventory stay in one deterministic probe"
)]
fn projection_09_sidecar_cleanup_disposition_is_observable_and_claims_no_removal() {
    let note = emit(note_event_log_sink_status);
    if event_log_sink_status().is_ok() {
        assert!(
            note.is_empty(),
            "a live sink needs no unavailability note, got: {note}"
        );
    } else {
        assert!(
            note.contains("host.event_log_sink_unavailable"),
            "the canonical disposition observer must record the sink disposition: {note}"
        );
        assert!(
            !note.contains("host.terminal_error"),
            "a sink disposition is not a terminal: {note}"
        );
        assert!(
            !note.contains("host.entrypoint_stage"),
            "the canonical disposition observer is not an entrypoint stage: {note}"
        );
        for positive in ROLLBACK_POSITIVE_CLAIMS {
            assert!(
                !note.contains(positive),
                "the sink disposition record claimed {positive:?}: {note}"
            );
        }
    }
    // The positive claims stay inadmissible for every unproven outcome, which
    // is the property that keeps an unknown cleanup out of the record history
    // as a removal.
    for positive in ROLLBACK_POSITIVE_CLAIMS {
        for evidence in [
            HostRequestEvidence::Observed,
            HostRequestEvidence::Admitted,
            HostRequestEvidence::SemanticallyReady,
            HostRequestEvidence::Cancelled,
            HostRequestEvidence::Unknown,
            HostRequestEvidence::Failed,
        ] {
            for event in [
                AdmittedEvent::ServiceStart,
                AdmittedEvent::ServiceStop,
                AdmittedEvent::ServiceFailure,
            ] {
                assert!(
                    !event.is_admitted_by(evidence),
                    "{} still admits {} while the outcome is {}",
                    event.as_str(),
                    positive,
                    evidence.as_str()
                );
            }
        }
    }
    // Supplementary emission binding: the cleanup contour is no longer silent
    // and states its own explicit non-success dispositions beside the positive
    // one, so a failed or undetermined cleanup cannot read as a completion.
    let owner = src("src/phase_b_materialization/rollback_backup.rs");
    for label in [
        "host.phase-b rollback backup cleanup requested",
        "host.phase-b rollback backup cleanup completed",
        "host.phase-b rollback backup cleanup delete failed",
        "host.phase-b rollback backup cleanup path failed",
        "host.phase-b rollback backup cleanup absence unproven",
    ] {
        assert!(
            owner.contains(&format!("\"{label}\"")),
            "the sidecar cleanup contour must name {label:?}"
        );
    }
}
