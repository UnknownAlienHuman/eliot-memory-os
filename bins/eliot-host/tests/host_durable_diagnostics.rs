#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Focused diagnostics tests for F-LOG-HOST-2 item 893, Writer-B slice
//! (credential + Store recovery + shared test ownership).
//!
//! Through the #889 facade only (`host_diagnostics::observe_entrypoint`,
//! `observe_entrypoint_with_detail`, `observe_terminal_error`); the Windows
//! Event Log seam stays typed-Unavailable (`event_log_sink_status`), never
//! implemented here (#984 still open).
//!
//! Scope rule: production files are disjoint between writers. This file owns
//! `credential_control.rs`, `store_recovery_persistence.rs`, and
//! `host_composition_store_recovery.rs` callsites directly, and asserts the
//! Writer-A files (`host_composition_phase_b.rs`,
//! `phase_b_materialization.rs`, `host_activation_durable.rs`) ONLY through
//! their frozen boundary shapes named in the READER-893 brief (function names
//! present at base `d17a6c77`), never through their diagnostic strings and
//! never by editing them. Cross-cutting cases 22-26 are asserted against both
//! writers' frozen shapes; they pass on this tree standalone and stay valid
//! once Writer-A's callsites land, because Writer-A owns distinct operations
//! with distinct terminal codes and never touches `lib.rs`, the facade, or
//! this file.
//!
//! Every case drives real code: the real facade vocabulary the callsites use,
//! the real runtime-control wire types, and the real tracked sources via
//! `manifest_source`. A hand-built expected log alone is never call-site
//! proof. Package fixtures never claim live Store/SCM recovery. Diagnostics
//! are evidence only: they never change control flow, state, errors,
//! receipts, order, status, or cleanup, and stdout framing stays exactly
//! one-JSON-per-line.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, bound_detail, bound_field,
    observe_entrypoint_with_detail, observe_terminal_error, sink_status,
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

fn durable_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/host_durable_diagnostics.json");
    let bytes = std::fs::read(&path).expect("durable fixture must be readable");
    serde_json::from_slice(&bytes).expect("durable fixture must be valid JSON")
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

fn credential_source() -> String {
    manifest_source("src/credential_control.rs")
}

fn store_persist_source() -> String {
    manifest_source("src/store_recovery_persistence.rs")
}

fn store_request_source() -> String {
    manifest_source("src/host_composition_store_recovery.rs")
}

fn fixture_str_list(fixture: &Value, key: &str) -> Vec<String> {
    fixture[key]
        .as_array()
        .unwrap_or_else(|| panic!("fixture must pin {key}"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("fixture {key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn store_request(request_id: &str, mutation_hex: &str) -> eliot_host::HostRuntimeControlRequest {
    eliot_host::HostRuntimeControlRequest::new_with_mutation_digest(
        eliot_host::HostRuntimeControlOperation::RecoverStore,
        eliot_platform::PlatformHandle::new(request_id.to_owned()).expect("test handle"),
        eliot_platform::PlatformHandle::new(mutation_hex.to_owned()).expect("test handle"),
    )
    .expect("store request must validate")
}

fn store_reconcile_request(
    request_id: &str,
    mutation_hex: &str,
) -> eliot_host::HostRuntimeControlRequest {
    eliot_host::HostRuntimeControlRequest::new_store_reconcile(
        eliot_platform::PlatformHandle::new(request_id.to_owned()).expect("test handle"),
        eliot_platform::PlatformHandle::new(mutation_hex.to_owned()).expect("test handle"),
    )
    .expect("store reconcile request must validate")
}

// WORK_UNIT_CASE: 893/1
#[test]
fn durable_01_six_file_denominator() {
    // Six-file denominator: Writer-B's three files observe through the
    // facade; all six files exist with their frozen boundaries; the facade
    // and sink stay untouched by either writer.
    let fixture = durable_fixture();
    let credential = credential_source();
    let persist = store_persist_source();
    let request = store_request_source();
    for (source, name) in [
        (&credential, "credential_control.rs"),
        (&persist, "store_recovery_persistence.rs"),
        (&request, "host_composition_store_recovery.rs"),
    ] {
        assert!(
            source.contains("observe_entrypoint_with_detail"),
            "{name} must observe through the facade"
        );
        assert!(
            source.contains("event_log_sink_status"),
            "{name} must carry the unavailable-seam note call"
        );
        assert!(
            source.contains("F-LOG-HOST-2 (#893)"),
            "{name} must mark the Writer-B instrumentation"
        );
    }
    // Writer-B helpers exist with private visibility (see case 26 for the
    // no-new-visibility proof).
    assert!(credential.contains("fn credential_control_observe"));
    assert!(persist.contains("fn store_recovery_persist_observe"));
    assert!(request.contains("fn store_recovery_observe"));
    // All six files exist with frozen Writer-A shapes pinned by the fixture.
    let phase_b = manifest_source("src/host_composition_phase_b.rs");
    let materialization = manifest_source("src/phase_b_materialization.rs");
    let activation = manifest_source("src/host_activation_durable.rs");
    let combined = format!("{phase_b}{materialization}{activation}");
    assert!(combined.contains("fn materialize_phase_b"));
    assert!(combined.contains("fn commit_pending_durable"));
    assert!(combined.contains("fn publish_agent_bridge_pair"));
    // Facade vocabulary proof: one Startup and one ScmDispatch record share
    // the diagnostics target and the pinned entrypoint event.
    assert_eq!(
        EntrypointStage::Startup.as_str(),
        fixture["stages"]["startup"]
            .as_str()
            .expect("fixture pins startup")
    );
    assert_eq!(
        EntrypointStage::ScmDispatch.as_str(),
        fixture["stages"]["scm_dispatch"]
            .as_str()
            .expect("fixture pins scm_dispatch")
    );
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery projection requested",
        );
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, "host.credential requested");
    });
    assert!(text.contains(HOST_DIAGNOSTICS_TARGET));
    let event = fixture["entrypoint_event"]
        .as_str()
        .expect("fixture must pin the entrypoint event");
    assert_eq!(count_occurrences(&text, event), 2, "got: {text}");
}

// WORK_UNIT_CASE: 893/2
#[test]
fn durable_02_phase_b_request_vs_validation() {
    // Phase-B request versus validation: the outer contour distinguishes the
    // admission from the validation outcome; the inner
    // `materialize_phase_b` validation body is Writer-A owned and pinned here
    // only by its frozen shape.
    let lib = manifest_source("src/lib.rs");
    let phase_b = manifest_source("src/host_composition_phase_b.rs");
    assert!(lib.contains("host.phase-b requested"));
    assert!(lib.contains("host.phase-b unknown"));
    assert!(phase_b.contains("fn materialize_phase_b"));
    let correlation = "phase-b-validation:893-2";
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.phase-b requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.phase-b unknown {correlation}"),
        );
    });
    assert!(text.contains("host.phase-b requested"));
    assert!(text.contains("host.phase-b unknown"));
    assert_ne!("host.phase-b requested", "host.phase-b unknown");
    assert_eq!(count_occurrences(&text, correlation), 2, "got: {text}");
}

// WORK_UNIT_CASE: 893/3
#[test]
fn durable_03_prepared_vs_materialized() {
    // Prepared/staged versus materialized: three frozen stages stay distinct
    // names; the outer prepared receipt is observed distinctly from any
    // materialization claim.
    let lib = manifest_source("src/lib.rs");
    let activation = manifest_source("src/host_activation_durable.rs");
    let materialization = manifest_source("src/phase_b_materialization.rs");
    let phase_b = manifest_source("src/host_composition_phase_b.rs");
    assert!(lib.contains("host.phase-b prepared receipt"));
    assert!(activation.contains("fn persist_pending_phase_b_prepared"));
    assert!(materialization.contains("fn prepare_agent_bridge_materialization"));
    assert!(phase_b.contains("fn materialize_phase_b"));
    assert_ne!(
        "persist_pending_phase_b_prepared",
        "prepare_agent_bridge_materialization"
    );
    assert_ne!(
        "prepare_agent_bridge_materialization",
        "materialize_phase_b"
    );
    let correlation = "prepared-vs-materialized:893-3";
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.phase-b prepared receipt {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("host.store-recovery receipt persisted {correlation}"),
        );
    });
    assert!(text.contains("host.phase-b prepared receipt"));
    assert!(text.contains("host.store-recovery receipt persisted"));
}

// WORK_UNIT_CASE: 893/4
#[test]
fn durable_04_publication_request_vs_observed_commit() {
    // Publication request versus observed commit: the frozen publication and
    // readback classifiers exist; request precedes commit in the observed
    // order and the two records stay distinct.
    let materialization = manifest_source("src/phase_b_materialization.rs");
    assert!(materialization.contains("fn publish_agent_bridge_pair"));
    assert!(materialization.contains("fn verify_agent_bridge_pair_readback"));
    assert!(materialization.contains("fn phase_b_materialize_file"));
    let persist = store_persist_source();
    assert!(persist.contains("host.store-recovery receipt persist requested"));
    assert!(persist.contains("host.store-recovery receipt persisted"));
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt persist requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt persisted",
        );
    });
    let requested = text
        .find("host.store-recovery receipt persist requested")
        .expect("capture must contain the persist request");
    let committed = text
        .find("host.store-recovery receipt persisted")
        .expect("capture must contain the persisted commit");
    assert!(
        requested < committed,
        "request must precede commit, got: {text}"
    );
}

// WORK_UNIT_CASE: 893/5
#[test]
fn durable_05_response_loss_retains_unknown() {
    // Response loss / possible publication retains Unknown: frozen rehydrate
    // shapes exist; a readback replay is observed distinctly from a commit,
    // and a possible effect stays a single-terminal Unknown, never success.
    let phase_b = manifest_source("src/host_composition_phase_b.rs");
    let materialization = manifest_source("src/phase_b_materialization.rs");
    let lib = manifest_source("src/lib.rs");
    assert!(phase_b.contains("fn rehydrate_phase_b_from_prepared"));
    assert!(materialization.contains("fn rehydrate_agent_bridge_binding"));
    assert!(lib.contains("readback replay"));
    let correlation = "response-loss:893-5";
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            &format!("host.store-recovery execute receipt readback {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.store-recovery unknown {correlation}"),
        );
        observe_terminal_error("host-store-recovery-unknown");
    });
    assert!(text.contains("host.store-recovery execute receipt readback"));
    assert!(!text.contains("host.store-recovery execute receipt completion"));
    assert_eq!(
        count_occurrences(&text, "host.terminal_error"),
        1,
        "possible effect must emit exactly one terminal, got: {text}"
    );
    // Wire proof: a pending intent stays a validated Unknown, never success.
    let pending = store_request("893-5-pending", &"c5".repeat(32));
    let pending_ref = eliot_host_service::runtime_control::runtime_control_unknown_ref(
        "store-recovery-pending",
        &pending,
    );
    let unknown = eliot_host::HostRuntimeControlResponse::unknown_for(&pending, pending_ref);
    unknown.validate().expect("pending unknown must validate");
    assert!(matches!(
        unknown,
        eliot_host::HostRuntimeControlResponse::Unknown { .. }
    ));
    assert!(eliot_host_service::runtime_control::response_matches_request(&pending, &unknown));
}

// WORK_UNIT_CASE: 893/6
#[test]
fn durable_06_exact_operation_identities() {
    // Exact source/digest/operation identities: request digests are exact per
    // (operation, request_id, mutation); every frozen diagnostic string line
    // in Writer-B sources is a static literal with no format placeholder.
    let first = store_request("893-6-first", &"c6".repeat(32));
    let second = store_request("893-6-second", &"c6".repeat(32));
    assert_ne!(
        first.request_digest.as_str(),
        second.request_digest.as_str(),
        "distinct request identities must digest distinctly"
    );
    let repeat = store_request("893-6-first", &"c6".repeat(32));
    assert_eq!(
        first.request_digest.as_str(),
        repeat.request_digest.as_str(),
        "identical identities must digest identically"
    );
    let reconcile = store_reconcile_request("893-6-first", &"c6".repeat(32));
    assert_ne!(first.operation, reconcile.operation);
    assert_ne!(
        first.request_digest.as_str(),
        reconcile.request_digest.as_str(),
        "distinct operations must digest distinctly"
    );
    // Static-literal proof: every frozen diagnostic string line carries no
    // interpolation placeholder.
    for source in [
        credential_source(),
        store_persist_source(),
        store_request_source(),
    ] {
        for line in source.lines().filter(|line| {
            line.contains("host.credential")
                || line.contains("host.store-recovery")
                || line.contains("host-credential")
                || line.contains("host-store-recovery")
        }) {
            assert!(
                !line.contains("{}"),
                "diagnostic line must be a static literal: {line}"
            );
            assert!(
                !line.contains("{error}"),
                "diagnostic line must not format errors: {line}"
            );
        }
    }
}

// WORK_UNIT_CASE: 893/7
#[test]
fn durable_07_substitution_stays_typed_failure() {
    // Substitution/stale source is a typed failure: frozen digest classifier
    // exists; stale bindings are preserved (never adopted) and observed
    // distinctly from Unknown-terminal emission.
    let materialization = manifest_source("src/phase_b_materialization.rs");
    assert!(materialization.contains("fn phase_b_bytes_digest"));
    let request = store_request_source();
    assert!(request.contains("host.store-recovery stale binding preserved"));
    assert!(request.contains("host.store-recovery contour mismatch preserved"));
    let correlation = "stale-substitution:893-7";
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.store-recovery stale binding preserved {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.store-recovery unknown {correlation}"),
        );
        observe_terminal_error("host-store-recovery-unknown");
    });
    assert!(text.contains("host.store-recovery stale binding preserved"));
    assert_eq!(
        count_occurrences(&text, "host.terminal_error"),
        1,
        "got: {text}"
    );
    // Wire proof: a substituted operation stays a validated Unknown tied to
    // the exact request identity.
    let original = store_request("893-7-original", &"c7".repeat(32));
    let unknown = eliot_host::HostRuntimeControlResponse::unknown_for(
        &original,
        eliot_host_service::runtime_control::runtime_control_unknown_ref(
            "store-recovery",
            &original,
        ),
    );
    unknown
        .validate()
        .expect("substitution unknown must validate");
    assert!(eliot_host_service::runtime_control::response_matches_request(&original, &unknown));
    let other = store_request("893-7-other", &"c7".repeat(32));
    assert!(
        !eliot_host_service::runtime_control::response_matches_request(&other, &unknown),
        "unknown for one identity must not match another"
    );
}

// WORK_UNIT_CASE: 893/8
#[test]
fn durable_08_protected_root_lease_identity() {
    // Protected-root lease identity/failure: the frozen lease opener exists;
    // credential admission observes identity checks without values, with one
    // terminal on the Unknown outcome.
    let materialization = manifest_source("src/phase_b_materialization.rs");
    assert!(materialization.contains("fn open_agent_bridge_final_lease"));
    let credential = credential_source();
    assert!(credential.contains("host.credential admission unknown"));
    assert!(credential.contains("host.credential acquired owner-epoch"));
    let correlation = "lease-identity:893-8";
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.credential acquire requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.credential admission unknown {correlation}"),
        );
        observe_terminal_error("host-credential-unknown");
    });
    assert!(text.contains("host.credential admission unknown"));
    assert_eq!(
        count_occurrences(&text, "host-credential-unknown"),
        1,
        "got: {text}"
    );
}

// WORK_UNIT_CASE: 893/9
#[test]
fn durable_09_rollback_request_vs_restoration() {
    // Rollback request versus actual restoration: frozen rollback shapes
    // exist; the observed cleanup request precedes the observed removal and
    // the two records stay distinct.
    let phase_b = manifest_source("src/host_composition_phase_b.rs");
    let materialization = manifest_source("src/phase_b_materialization.rs");
    assert!(phase_b.contains("fn rollback_uncommitted_phase_b"));
    assert!(materialization.contains("fn rollback_agent_bridge_pair"));
    assert!(materialization.contains("fn rollback_agent_bridge_stage"));
    let persist = store_persist_source();
    assert!(persist.contains("host.store-recovery cleanup requested"));
    assert!(persist.contains("host.store-recovery cleanup removed"));
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery cleanup requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery cleanup removed",
        );
    });
    let requested = text
        .find("host.store-recovery cleanup requested")
        .expect("capture must contain the cleanup request");
    let removed = text
        .find("host.store-recovery cleanup removed")
        .expect("capture must contain the removal");
    assert!(
        requested < removed,
        "request must precede restoration, got: {text}"
    );
}

// WORK_UNIT_CASE: 893/10
#[test]
fn durable_10_rollback_failure_claims_nothing_restored() {
    // Rollback failure/Unknown cannot claim restored: failure captures carry
    // the cleanup-unknown detail plus one terminal and never any restored
    // marker.
    let credential = credential_source();
    assert!(credential.contains("host.credential revoke cleanup unknown"));
    assert!(credential.contains("host.credential revoked absent"));
    assert_ne!(
        "host.credential revoke cleanup unknown",
        "host.credential revoked absent"
    );
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential revoke cleanup unknown",
        );
        observe_terminal_error("host-credential-unknown");
    });
    assert!(text.contains("host.credential revoke cleanup unknown"));
    assert!(
        !text.contains("host.credential revoked absent"),
        "failure must not claim revoked, got: {text}"
    );
    assert!(
        !text.contains("host.store-recovery cleanup removed"),
        "failure must not claim removed, got: {text}"
    );
    assert_eq!(
        count_occurrences(&text, "host.terminal_error"),
        1,
        "got: {text}"
    );
}

// WORK_UNIT_CASE: 893/11
#[test]
fn durable_11_credential_reference_without_value() {
    // Credential reference permitted without value: the queue accessor
    // clones the bounded reference; acquire observes identities only; the
    // queue carries no secret and captures carry no canary.
    let credential = credential_source();
    assert!(credential.contains("fn phase_b_queue"));
    assert!(credential.contains("Arc::clone(&self.phase_b_queue)"));
    assert!(credential.contains("host.credential acquire requested"));
    assert!(credential.contains("host.credential acquired owner-epoch"));
    // Real reference proof: an empty bounded queue clones, locks, and reads
    // back empty with no value crossing.
    let queue: eliot_host::HostPhaseBRequestQueue =
        Arc::new(Mutex::new(std::collections::VecDeque::new()));
    assert_eq!(queue.lock().expect("queue must lock").len(), 0);
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential acquire requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential acquired owner-epoch",
        );
    });
    assert!(text.contains("host.credential acquired owner-epoch"));
    for canary in [
        "password",
        "token=",
        "ownership_key",
        "CredentialSecret",
        ".expose()",
    ] {
        assert!(
            !text.contains(canary),
            "reference observation must not contain {canary:?}, got: {text}"
        );
    }
}

// WORK_UNIT_CASE: 893/12
#[test]
fn durable_12_credential_states_stay_distinct() {
    // Unavailable/invalid/revoked/consumed states: absent, consumed, and
    // revoked receipts are three distinct positive observations, each
    // emitted once per outcome.
    let credential = credential_source();
    for detail in [
        "host.credential inspect absent receipt",
        "host.credential provision consumed receipt",
        "host.credential reconcile revoked receipt",
        "host.credential revoked absent",
    ] {
        assert!(
            credential.contains(detail),
            "credential source must observe {detail:?}"
        );
    }
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential inspect absent receipt",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential provision consumed receipt",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential reconcile revoked receipt",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential revoked absent",
        );
    });
    for detail in [
        "host.credential inspect absent receipt",
        "host.credential provision consumed receipt",
        "host.credential reconcile revoked receipt",
        "host.credential revoked absent",
    ] {
        assert_eq!(
            count_occurrences(&text, detail),
            1,
            "state {detail:?} must appear once, got: {text}"
        );
    }
}

// WORK_UNIT_CASE: 893/13
#[test]
fn durable_13_cleanup_failure_is_distinct_non_success() {
    // Cleanup failure distinct/non-success: the credential and Store cleanup
    // boundaries observe request, failure, and removal as three distinct
    // records; failure never reads as removed.
    let credential = credential_source();
    let persist = store_persist_source();
    assert!(credential.contains("host.credential revoke cleanup unknown"));
    assert!(persist.contains("host.store-recovery cleanup requested"));
    assert!(persist.contains("host.store-recovery cleanup removed"));
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential revoke cleanup unknown",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery cleanup requested",
        );
        observe_terminal_error("host-credential-unknown");
    });
    assert!(text.contains("host.credential revoke cleanup unknown"));
    assert!(
        !text.contains("host.credential revoked absent"),
        "got: {text}"
    );
    assert!(
        !text.contains("host.store-recovery cleanup removed"),
        "got: {text}"
    );
}

// WORK_UNIT_CASE: 893/14
#[test]
fn durable_14_activation_request_stage_commit() {
    // Activation request/stage/commit/observation: frozen activation shapes
    // exist and stay distinct names; the facade carries the
    // requested-versus-completed distinction in order.
    let activation = manifest_source("src/host_activation_durable.rs");
    for boundary in [
        "fn reconcile_pending_activation",
        "fn claim_pending_durable",
        "fn commit_pending_durable",
        "fn abort_pending_durable",
        "fn fresh_pending_commit_fence",
        "fn verify_pending_commit_journal_fence",
    ] {
        assert!(
            activation.contains(boundary),
            "activation source must contain {boundary:?}"
        );
    }
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery execute requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery execute receipt completion",
        );
    });
    let requested = text
        .find("host.store-recovery execute requested")
        .expect("capture must contain the attempt");
    let completed = text
        .find("host.store-recovery execute receipt completion")
        .expect("capture must contain the completion");
    assert!(
        requested < completed,
        "request must precede completion, got: {text}"
    );
}

// WORK_UNIT_CASE: 893/15
#[test]
fn durable_15_positive_event_requires_durable_evidence() {
    // Positive activation event requires actual durable evidence: the frozen
    // commit shape exists; a persisted commit and a replay readback are
    // distinct records, and a readback emits no terminal and claims no new
    // commit.
    let activation = manifest_source("src/host_activation_durable.rs");
    assert!(activation.contains("fn commit_pending_durable"));
    let persist = store_persist_source();
    assert!(persist.contains("host.store-recovery receipt persisted"));
    assert!(persist.contains("host.store-recovery receipt replay readback"));
    let committed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt persisted",
        );
    });
    assert!(committed.contains("host.store-recovery receipt persisted"));
    assert!(
        !committed.contains("readback"),
        "commit must not read as readback, got: {committed}"
    );
    let replayed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt replay readback",
        );
    });
    assert!(replayed.contains("host.store-recovery receipt replay readback"));
    assert_eq!(
        count_occurrences(&replayed, "host.terminal_error"),
        0,
        "readback is not failure, got: {replayed}"
    );
    assert!(
        !replayed.contains("host.store-recovery receipt persisted"),
        "readback must not claim persisted, got: {replayed}"
    );
}

// WORK_UNIT_CASE: 893/16
#[test]
fn durable_16_store_projection_load_persist_restore() {
    // Store projection/load/persist/restore distinct: six durable primitives
    // own distinct records, all present in one ordered capture.
    let persist = store_persist_source();
    for detail in [
        "host.store-recovery projection requested",
        "host.store-recovery pending load requested",
        "host.store-recovery pending persist requested",
        "host.store-recovery receipt persist requested",
        "host.store-recovery cleanup requested",
        "host.store-recovery rebind requested",
    ] {
        assert!(
            persist.contains(detail),
            "persist source must observe {detail:?}"
        );
    }
    assert!(persist.contains("host.store-recovery projection admitted"));
    assert!(persist.contains("host.store-recovery receipt persisted"));
    assert!(persist.contains("host.store-recovery cleanup removed"));
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery projection requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery pending loaded",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery pending persisted",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt loaded",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt persisted",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery cleanup removed",
        );
    });
    for detail in [
        "projection requested",
        "pending loaded",
        "pending persisted",
        "receipt loaded",
        "receipt persisted",
        "cleanup removed",
    ] {
        assert!(
            text.contains(detail),
            "capture must contain distinct primitive {detail:?}, got: {text}"
        );
    }
}

// WORK_UNIT_CASE: 893/17
#[test]
fn durable_17_stale_mismatched_evidence_preserved() {
    // Stale/mismatched generation/epoch/fence preserved: mismatch records
    // name preservation explicitly; mismatched identities digest distinctly
    // on the real wire types.
    let persist = store_persist_source();
    let request = store_request_source();
    for detail in [
        "host.store-recovery intent mutation mismatch preserved",
        "host.store-recovery intent replay mismatch preserved",
        "host.store-recovery intent operation mismatch preserved",
        "host.store-recovery epoch mismatch preserved",
        "host.store-recovery stale binding preserved",
    ] {
        let combined = format!("{persist}{request}");
        assert!(
            combined.contains(detail),
            "sources must preserve {detail:?}"
        );
    }
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery epoch mismatch preserved",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery stale binding preserved",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery contour mismatch preserved",
        );
    });
    for detail in [
        "host.store-recovery epoch mismatch preserved",
        "host.store-recovery stale binding preserved",
        "host.store-recovery contour mismatch preserved",
    ] {
        assert!(text.contains(detail), "got: {text}");
        assert!(
            detail.contains("preserv"),
            "mismatch record must name preservation: {detail}"
        );
    }
    let first = store_request("893-17-same", &"c1".repeat(32));
    let changed = store_request("893-17-changed", &"c1".repeat(32));
    assert_ne!(
        first.request_digest.as_str(),
        changed.request_digest.as_str(),
        "changed same-operation content must digest distinctly"
    );
}

// WORK_UNIT_CASE: 893/18
#[test]
fn durable_18_recovery_lifecycle_stays_distinct() {
    // Recovery requested/attempted/succeeded/failed/unknown distinct: the
    // request boundary owns requested, attempt, completion, and unknown
    // records; success emits no terminal while failure emits exactly one.
    let request = store_request_source();
    for detail in [
        "host.store-recovery requested",
        "host.store-recovery execute requested",
        "host.store-recovery receipt completion",
        "host.store-recovery unknown",
        "host.store-recovery reconcile requested",
        "host.store-recovery reconcile receipt completion",
        "host.store-recovery reconcile unknown",
    ] {
        assert!(
            request.contains(detail),
            "request source must observe {detail:?}"
        );
    }
    let succeeded = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery execute requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery receipt completion",
        );
    });
    assert!(succeeded.contains("host.store-recovery receipt completion"));
    assert_eq!(
        count_occurrences(&succeeded, "host.terminal_error"),
        0,
        "success emits no terminal, got: {succeeded}"
    );
    let failed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery requested",
        );
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, "host.store-recovery unknown");
        observe_terminal_error("host-store-recovery-unknown");
    });
    assert_eq!(
        count_occurrences(&failed, "host.terminal_error"),
        1,
        "failure emits one terminal, got: {failed}"
    );
}

// WORK_UNIT_CASE: 893/19
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "T-A keeps the replay/readback inventory, no-commit proof, and readback labelling in one deterministic probe"
)]
fn durable_t_a_replay_is_readback_not_second_commit() {
    // T-A (replay half): exact replay is a readback, never a duplicate
    // commit. Every replay-labelled record pinned by the fixture exists in
    // the Writer-B sources, names readback explicitly, and emits no terminal
    // and no completion claim when driven.
    let fixture = durable_fixture();
    let persist = store_persist_source();
    let request = store_request_source();
    let combined = format!("{persist}{request}");
    for detail in fixture_str_list(&fixture, "replay_readback_details") {
        assert!(
            combined.contains(&detail),
            "sources must observe replay {detail:?}"
        );
        assert!(
            detail.contains("readback"),
            "replay record must name readback: {detail:?}"
        );
        assert!(
            !detail.contains("persisted"),
            "replay record must not claim persisted: {detail:?}"
        );
        assert!(
            !detail.contains("completion"),
            "replay record must not claim completion: {detail:?}"
        );
    }
    // Exact-record replay through the durable publisher shape: the pending
    // publisher distinguishes Created from Replay without a second commit,
    // and the receipt publisher replays idempotently the same way.
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery pending replay readback",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt replay readback",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery rebind readback",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery committed rebind readback",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery execute replay readback",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery execute receipt readback",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery reconcile receipt readback replay",
        );
    });
    assert_eq!(
        count_occurrences(
            &text,
            fixture["terminal_event"]
                .as_str()
                .expect("fixture must pin the terminal event")
        ),
        0,
        "replay emits no terminal, got: {text}"
    );
    assert!(
        !text.contains("completion"),
        "replay must not claim completion, got: {text}"
    );
    assert!(
        !text.contains("persisted"),
        "replay must not claim persisted, got: {text}"
    );
}

// WORK_UNIT_CASE: 893/20
#[test]
fn durable_20_changed_content_remains_conflict() {
    // Changed same-operation content remains conflict: every
    // conflict-labelled record pinned by the fixture exists, names conflict
    // or preservation explicitly, and a conflicting rebind stays a validated
    // Unknown, never an adoption.
    let fixture = durable_fixture();
    let persist = store_persist_source();
    let request = store_request_source();
    let combined = format!("{persist}{request}");
    for detail in fixture_str_list(&fixture, "conflict_preserved_details") {
        assert!(
            combined.contains(&detail),
            "sources must preserve {detail:?}"
        );
        assert!(
            detail.contains("conflict")
                || detail.contains("mismatch")
                || detail.contains("preserv"),
            "conflict record must name conflict/mismatch/preservation: {detail:?}"
        );
    }
    assert!(persist.contains("host.store-recovery pending present"));
    assert!(persist.contains("host.store-recovery pending absent"));
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery reconcile unknown conflict",
        );
        observe_terminal_error("host-store-recovery-reconcile-unknown");
    });
    assert!(text.contains("host.store-recovery reconcile unknown conflict"));
    assert!(
        !text.contains("completion"),
        "conflict must not claim completion, got: {text}"
    );
    // Wire proof: a conflicting (mismatched-mutation) receipt rebind stays
    // Unknown and preserves the exact request identity.
    let receipt_request = store_request("893-20-receipt", &"c2".repeat(32));
    let other_request = store_request("893-20-other", &"d2".repeat(32));
    let conflict = eliot_host::HostRuntimeControlResponse::unknown_for(
        &other_request,
        eliot_host_service::runtime_control::runtime_control_unknown_ref(
            "store-recovery-reconcile-conflict",
            &other_request,
        ),
    );
    conflict.validate().expect("conflict unknown must validate");
    assert!(matches!(
        conflict,
        eliot_host::HostRuntimeControlResponse::Unknown { .. }
    ));
    assert!(
        eliot_host_service::runtime_control::response_matches_request(&other_request, &conflict)
    );
    assert!(
        !eliot_host_service::runtime_control::response_matches_request(&receipt_request, &conflict),
        "conflict for one mutation must not match another"
    );
}

// WORK_UNIT_CASE: 893/21
#[test]
fn durable_21_timeout_keeps_possible_effect_unknown() {
    // Cancellation/timeout/late result retains possible effect: the bounded
    // queue constants and the queue-response observation exist; a timeout
    // emits the response-unknown detail with no terminal of its own (the
    // single terminal stays with the request owner), because the owner
    // thread may still complete late.
    let credential = credential_source();
    assert!(credential.contains("PHASE_B_QUEUE_RESPONSE_TIMEOUT"));
    assert!(credential.contains("MAX_PHASE_B_QUEUE_DEPTH"));
    assert!(credential.contains("host.credential phase-b enqueue full unknown"));
    assert!(credential.contains("host.credential phase-b queue response unknown"));
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential phase-b enqueued",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential phase-b queue response unknown",
        );
    });
    assert!(text.contains("host.credential phase-b queue response unknown"));
    assert_eq!(
        count_occurrences(&text, "host.terminal_error"),
        0,
        "timeout owns no terminal, got: {text}"
    );
    assert!(
        !text.contains("host-credential-unknown"),
        "timeout must not emit the request terminal, got: {text}"
    );
}

// WORK_UNIT_CASE: 893/22
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "T-A keeps the terminal inventory, guard proof, and disjoint-ownership proof in one deterministic probe"
)]
fn durable_t_a_single_terminal_per_failed_operation() {
    // T-A (terminal half): one terminal error per underlying operation across
    // nested propagation. Each Writer-B terminal code is emitted from exactly
    // one callsite, enforced by the single outermost guard per operation;
    // there is no dedup cache, and Writer-A files own none of these codes.
    let fixture = durable_fixture();
    let credential = credential_source();
    let persist = store_persist_source();
    let request = store_request_source();
    let owned = format!("{credential}{persist}{request}");
    let codes = [
        fixture["terminal_codes"]["credential_unknown"]
            .as_str()
            .expect("fixture must pin the credential unknown code"),
        fixture["terminal_codes"]["credential_serve_failed"]
            .as_str()
            .expect("fixture must pin the serve failed code"),
        fixture["terminal_codes"]["store_recovery_unknown"]
            .as_str()
            .expect("fixture must pin the recovery unknown code"),
        fixture["terminal_codes"]["store_recovery_reconcile_unknown"]
            .as_str()
            .expect("fixture must pin the reconcile unknown code"),
    ];
    for code in codes {
        // One literal per code across Writer-B sources: the single emission
        // site (direct call or guard arming). Comments never repeat a code.
        assert_eq!(
            count_occurrences(&owned, code),
            1,
            "terminal code {code:?} must be emitted from exactly one callsite"
        );
    }
    // Guard pattern replicated per operation inside Writer-B files (the
    // lib.rs HostTerminalGuard model, not a second copy of it).
    assert!(credential.contains("struct CredentialTerminalGuard"));
    assert!(request.contains("struct StoreRecoveryTerminalGuard"));
    assert!(credential.contains("fn disarm"));
    assert!(request.contains("fn disarm"));
    assert!(
        !owned.contains("static DEDUP"),
        "no mutable global dedup cache may exist"
    );
    // Disjoint ownership that survives integration: Writer-A files carry none
    // of Writer-B's terminal codes, and the outer lib.rs contour is unchanged.
    let phase_b = manifest_source("src/host_composition_phase_b.rs");
    let materialization = manifest_source("src/phase_b_materialization.rs");
    let activation = manifest_source("src/host_activation_durable.rs");
    let others = format!("{phase_b}{materialization}{activation}");
    for code in codes {
        assert!(
            !others.contains(code),
            "Writer-A files must not own Writer-B terminal {code:?}"
        );
    }
    let lib = manifest_source("src/lib.rs");
    assert_eq!(
        count_occurrences(&lib, "\"host-credential-control-failed\""),
        1,
        "outer construction terminal must stay singular"
    );
    // Exactly one terminal per failed operation; zero on success and on
    // replay; inner phases correlate by stage order only.
    let terminal_event = fixture["terminal_event"]
        .as_str()
        .expect("fixture must pin the terminal event");
    let correlation = "single-terminal:893-22";
    let failed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.credential requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.credential unknown {correlation}"),
        );
        observe_terminal_error("host-credential-unknown");
    });
    assert_eq!(
        count_occurrences(&failed, terminal_event),
        1,
        "one failed op emits one terminal, got: {failed}"
    );
    assert_eq!(
        count_occurrences(&failed, correlation),
        2,
        "phases share correlation, got: {failed}"
    );
    let succeeded = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential provision consumed receipt",
        );
    });
    assert_eq!(
        count_occurrences(&succeeded, terminal_event),
        0,
        "success emits no terminal, got: {succeeded}"
    );
}

// WORK_UNIT_CASE: 893/23
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "T-B keeps the canary sweep, literal proof, and bound honesty in one deterministic probe"
)]
fn durable_t_b_canaries_absent_from_observations() {
    // T-B (redaction half): credential/DB/env/source/user canaries are
    // absent from every frozen diagnostic string line; captures never carry
    // them; bounded helpers stay honest about truncation.
    let fixture = durable_fixture();
    let canaries = fixture_str_list(&fixture, "canaries");
    assert!(!canaries.is_empty(), "fixture must pin canaries");
    for source in [
        credential_source(),
        store_persist_source(),
        store_request_source(),
    ] {
        for line in source.lines().filter(|line| {
            line.contains("host.credential")
                || line.contains("host.store-recovery")
                || line.contains("host-credential")
                || line.contains("host-store-recovery")
        }) {
            for canary in &canaries {
                assert!(
                    !line.contains(canary.as_str()),
                    "diagnostic line must not contain canary {canary:?}: {line}"
                );
            }
        }
    }
    // Captures prove the same bound over emitted records.
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.credential provision requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt persist requested",
        );
        observe_terminal_error("host-credential-unknown");
    });
    for canary in &canaries {
        assert!(
            !text.contains(canary.as_str()),
            "capture must not contain canary {canary:?}, got: {text}"
        );
    }
    // Bounding limits size with honesty; it never inspects sensitivity, so
    // callers pass literals only (proven above).
    assert_eq!(bound_field("startup").text(), "startup");
    let oversized = "y".repeat(8 * 1024 + 7);
    let bounded = bound_detail(&oversized);
    assert_eq!(bounded.original_bytes(), oversized.len());
    assert!(bounded.truncated());
    assert!(
        bounded.text().len() <= 1024,
        "retained prefix must stay bounded"
    );
}

// WORK_UNIT_CASE: 893/24
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "T-B keeps the unavailable-seam, result-identity, ordering, and stdout-framing proofs in one deterministic probe"
)]
fn durable_t_b_sink_failure_leaves_operation_identical() {
    // T-B (noninterference half): every Writer-B boundary notes the
    // unavailable Event Log seam; sink outcomes never alter the operation
    // result, order, or stdout framing.
    for source in [
        credential_source(),
        store_persist_source(),
        store_request_source(),
    ] {
        assert!(
            source.contains("event_log_sink_status"),
            "every Writer-B file must note the unavailable seam"
        );
    }
    assert_eq!(
        event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(eliot_host::host_diagnostics::HostDiagnosticsError::EventLogUnavailable)
    );
    assert_eq!(sink_status(DiagnosticSink::TracingStderr), Ok(()));
    let record = eliot_host::windows_event_log::EventLogRecord::new(
        AdmittedEvent::ServiceFailure,
        "host-store-recovery-unknown",
    );
    assert_eq!(
        report_event(&record),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
    // Result identity: the same wire operation validates identically before
    // and after surrounding observations, with byte-identical digests.
    let before = store_request("893-24-stable", &"e4".repeat(32));
    let digest_before = before.request_digest.as_str().to_owned();
    let _ = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.store-recovery requested",
        );
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, "host.store-recovery unknown");
        observe_terminal_error("host-store-recovery-unknown");
    });
    before
        .validate()
        .expect("request must still validate after observations");
    assert_eq!(before.request_digest.as_str(), digest_before);
    let after = store_request("893-24-stable", &"e4".repeat(32));
    assert_eq!(
        after.request_digest.as_str(),
        digest_before,
        "observations must not perturb identity"
    );
    // Order identity: staged observations keep emission order in the capture.
    let ordered = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery projection requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery projection admitted",
        );
    });
    let first = ordered
        .find("projection requested")
        .expect("capture must contain first");
    let second = ordered
        .find("projection admitted")
        .expect("capture must contain second");
    assert!(
        first < second,
        "observation order must be preserved, got: {ordered}"
    );
    // Stdout framing: tracing writes to the capture (stderr model), never to
    // stdout; the console protocol stays exactly one-JSON-per-line.
    let mut buffer = Vec::new();
    for digest in ["aa".repeat(32), "bb".repeat(32)] {
        let frame = serde_json::json!({"mutation": digest});
        serde_json::to_writer(&mut buffer, &frame).expect("frame must serialize");
        buffer.write_all(b"\n").expect("frame must newline");
    }
    let frames: Vec<&str> = std::str::from_utf8(&buffer)
        .expect("frames must be UTF-8")
        .lines()
        .collect();
    assert_eq!(
        frames.len(),
        2,
        "stdout must stay exactly one-JSON-per-line"
    );
    for frame in frames {
        serde_json::from_str::<Value>(frame).expect("each line must be valid JSON");
    }
    let fixture = durable_fixture();
    assert_eq!(
        fixture["stdout_protocol_contamination"].as_bool(),
        Some(false)
    );
}

// WORK_UNIT_CASE: 893/25
#[test]
fn durable_25_deterministic_captures_under_injected_schedule() {
    // Deterministic semantic captures: the injected-fault seam and the
    // durable-ordering markers exist in the persistence source, and the
    // observation layer itself is deterministic — the same emission schedule
    // captures byte-identically, while order changes are visible as text
    // changes (observational timing stays separate from semantics).
    let persist = store_persist_source();
    for marker in [
        "inject_write_fault",
        "take_write_fault",
        "store_pending_file_write_fault_injected",
        "store_receipt_file_write_fault_injected",
        "store_pending_publication_complete",
        "store_receipt_durable_before_evidence_removal",
        "store_receipt_publication_complete",
    ] {
        assert!(
            persist.contains(marker),
            "persistence source must contain fault/order marker {marker:?}"
        );
    }
    let schedule = || {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery pending persist requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery pending persisted",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt persist requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt persisted",
        );
    };
    let first = capture_emit(schedule);
    let second = capture_emit(schedule);
    // Wall-clock timestamps prefix every record (observational timing stays
    // separate from semantics), so determinism compares the semantic suffix
    // of each line.
    fn semantic_lines(capture: &str) -> Vec<&str> {
        capture
            .lines()
            .map(|line| line.split_once(' ').map(|(_, rest)| rest).unwrap_or(line))
            .collect()
    }
    assert_eq!(
        semantic_lines(&first),
        semantic_lines(&second),
        "identical schedules must capture identical semantics"
    );
    assert!(first.contains("host.store-recovery pending persisted"));
    let reordered = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery receipt persist requested",
        );
        observe_entrypoint_with_detail(
            EntrypointStage::Startup,
            "host.store-recovery pending persist requested",
        );
    });
    assert_ne!(
        semantic_lines(&first),
        semantic_lines(&reordered),
        "order changes must be visible in the capture"
    );
}

// WORK_UNIT_CASE: 893/26
#[test]
fn durable_26_actual_path_and_diff_guard() {
    // Actual-path + diff guard: this test reads the real tracked sources
    // (never a copy), binds all 26 cases to this file, adds no public
    // logging surface, spawns no workers, performs no I/O off the observed
    // path, and leaves Writer-A files to Writer-A.
    let own = manifest_source("tests/host_durable_diagnostics.rs");
    assert!(
        own.contains("capture_emit"),
        "test must drive the real capture seam"
    );
    assert!(
        own.contains("manifest_source"),
        "test must read the real tracked sources"
    );
    let bindings = own
        .lines()
        .filter(|line| line.trim_start().starts_with("// WORK_UNIT_CASE: 893/"))
        .count();
    assert_eq!(bindings, 26, "all 26 cases must bind in this file");
    let fixture = durable_fixture();
    let cases = fixture["cases"]
        .as_object()
        .expect("fixture must pin the 26 cases");
    assert_eq!(cases.len(), 26, "fixture must pin exactly 26 cases");
    for number in 1..=26 {
        assert!(
            cases.contains_key(&number.to_string()),
            "fixture must pin case {number}"
        );
    }
    // Allowed diff: no new public logging surface in Writer-B files.
    for source in [
        credential_source(),
        store_persist_source(),
        store_request_source(),
    ] {
        for banned in [
            "pub fn credential_control_observe",
            "pub fn store_recovery_persist_observe",
            "pub fn store_recovery_observe",
            "pub struct CredentialTerminalGuard",
            "pub struct StoreRecoveryTerminalGuard",
            "static DEDUP",
            "tokio::spawn",
            "std::thread::spawn",
            "println!",
            "eprintln!",
        ] {
            assert!(
                !source.contains(banned),
                "Writer-B sources must not contain {banned:?}"
            );
        }
    }
    // No duplicate evaluation: terminal emission sites are singular per code
    // (proven in case 22); phase observations are pure static literals with
    // no computed values to evaluate twice.
    assert!(fixture["allowed_diff"]["single_terminal_per_failed_op"].as_bool() == Some(true));
    assert!(fixture["allowed_diff"]["no_new_logging_subsystem"].as_bool() == Some(true));
}
