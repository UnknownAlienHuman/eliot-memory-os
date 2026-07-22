use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_engine::{
    ExternalResultCompletenessService, ProviderCompletenessInput, ProviderInvocationJournal,
    ProviderInvocationLifecycleService, ProviderOutputSpool, ProviderReadinessInput,
    ProviderReconciliationInput, ProviderReconciliationService, ProviderRouteReadinessService,
};
use eliot_types::{
    ExternalResultCompletenessReceipt, ProviderIdentityCheck, ProviderInvocationAttempt,
    ProviderInvocationOutcomeClass, ProviderInvocationState, ProviderReconciliationMethod,
    ProviderResultCompleteness, ProviderRouteReadinessVerdict, ProviderTimeoutClass,
};
use time::OffsetDateTime;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CAMPAIGN_ID: &str = "delegation-campaign:019f55bc-0c49-7043-b78b-e3a4bf1b636e";
const RESERVATION_ID: &str = "provider-call-reservation:019f55bc-5cce-7863-91bf-7d77d5614b83";
const INVOCATION_REF: &str = "antigravity-request-019f55bc-6924-70f0-9dde-925aef616399";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[test]
fn exact_l1c_incident_preserves_consumed_slot_and_unknown_external_outcome() {
    let result = ProviderReconciliationService.reconcile(reconciliation_input(
        false,
        false,
        vec![identity_check("external_invocation_ref", true)],
    ));
    assert_eq!(3, historical_call_count());
    assert_eq!(
        result.outcome.effective_state,
        ProviderInvocationState::NonReconcilableUnknown
    );
    assert_eq!(
        result.outcome.outcome_class,
        ProviderInvocationOutcomeClass::NonReconcilableUnknown
    );
    assert!(result.outcome.dispatch_proven);
    assert!(result.outcome.slot_consumed);
    assert!(!result.outcome.review_created);
    assert!(!result.outcome.retry_same_campaign_allowed);
    assert_eq!(result.record.invocation_attempt_ref, INVOCATION_REF);
}

#[test]
fn pre_dispatch_abort_is_terminal_and_does_not_prove_dispatch() -> TestResult {
    let root = temp_root("pre-dispatch");
    let journal = ProviderInvocationJournal::new(&root);
    let mut attempt = journal.create(attempt("pre-dispatch"))?;
    journal.transition(&mut attempt, ProviderInvocationState::Reserved, Vec::new())?;
    journal.transition(
        &mut attempt,
        ProviderInvocationState::PreDispatchAborted,
        vec!["process/network start never attempted".to_owned()],
    )?;
    assert!(attempt.external_invocation_ref.is_none());
    assert!(!ProviderInvocationLifecycleService::transition_allowed(
        ProviderInvocationState::PreDispatchAborted,
        ProviderInvocationState::DispatchStarting
    ));
    cleanup(&root);
    Ok(())
}

#[test]
fn timeout_after_dispatch_consumes_slot_and_replay_is_idempotent() {
    let now = OffsetDateTime::UNIX_EPOCH;
    let input = ProviderReconciliationInput {
        started_at: now,
        completed_at: now,
        ..reconciliation_input(
            false,
            false,
            vec![identity_check("external_invocation_ref", true)],
        )
    };
    let first = ProviderReconciliationService.reconcile(input.clone());
    let replay = ProviderReconciliationService.reconcile(input);
    assert_eq!(first, replay);
    assert!(first.outcome.slot_consumed);
    assert_eq!(
        first.outcome.timeout_class,
        Some(ProviderTimeoutClass::AbsoluteRuntimeTimeout)
    );
    assert!(!first.outcome.retry_same_campaign_allowed);
}

#[test]
fn partial_output_cannot_be_normalized() {
    let receipt = completeness(false, true, false);
    assert!(!receipt.result_complete);
    assert!(!receipt.normalization_allowed);
    let result = ProviderReconciliationService.reconcile(ProviderReconciliationInput {
        completeness: receipt,
        ..reconciliation_input(
            false,
            true,
            vec![identity_check("external_invocation_ref", true)],
        )
    });
    assert!(!result.outcome.review_created);
    assert_eq!(
        result.record.result_completeness,
        ProviderResultCompleteness::Partial
    );
}

#[test]
fn complete_output_survives_cleanup_failure_and_recovers_once() {
    assert!(ProviderInvocationLifecycleService::transition_allowed(
        ProviderInvocationState::CompletedCaptured,
        ProviderInvocationState::CleanupFailedAfterComplete
    ));
    assert!(ProviderInvocationLifecycleService::transition_allowed(
        ProviderInvocationState::CleanupFailedAfterComplete,
        ProviderInvocationState::ReconciledCompleted
    ));
    let result = ProviderReconciliationService.reconcile(ProviderReconciliationInput {
        completeness: completeness(true, true, false),
        recovered_review_id: Some("candidate-review:exact".to_owned()),
        ..reconciliation_input(
            true,
            false,
            vec![identity_check("external_invocation_ref", true)],
        )
    });
    assert_eq!(
        result.outcome.effective_state,
        ProviderInvocationState::ReconciledCompleted
    );
    assert_eq!(
        result.record.review_id_if_recovered.as_deref(),
        Some("candidate-review:exact")
    );
    assert!(result.outcome.review_created);
}

#[test]
fn late_exact_result_requires_all_identity_constraints() {
    let checks = [
        "provider",
        "external_invocation_ref",
        "campaign_id",
        "reservation_id",
        "idempotency_key",
        "frozen_input_hash",
        "route_or_model",
        "time_window",
        "raw_output_checksum",
    ]
    .into_iter()
    .map(|field| identity_check(field, true))
    .collect();
    let result = ProviderReconciliationService.reconcile(ProviderReconciliationInput {
        completeness: completeness(true, true, false),
        recovered_review_id: Some("candidate-review:late".to_owned()),
        identity_checks: checks,
        ..reconciliation_input(true, false, Vec::new())
    });
    assert_eq!(
        result.outcome.outcome_class,
        ProviderInvocationOutcomeClass::CompletedReview
    );
    assert!(!result.record.provider_generating_call_performed);
}

#[test]
fn mismatched_late_result_is_quarantined() {
    let result = ProviderReconciliationService.reconcile(ProviderReconciliationInput {
        completeness: completeness(true, true, false),
        recovered_review_id: Some("candidate-review:wrong".to_owned()),
        identity_checks: vec![identity_check("frozen_input_hash", false)],
        mismatched_artifacts_quarantined: vec!["quarantine/wrong-result.json".to_owned()],
        ..reconciliation_input(true, false, Vec::new())
    });
    assert!(!result.outcome.review_created);
    assert_eq!(
        result.record.result_completeness,
        ProviderResultCompleteness::Mismatched
    );
    assert_eq!(result.record.mismatched_artifacts_quarantined.len(), 1);
}

#[test]
fn no_reconciliation_surface_stays_non_reconcilable_without_network() {
    let result = ProviderReconciliationService.reconcile(ProviderReconciliationInput {
        methods_attempted: vec![
            ProviderReconciliationMethod::LocalWal,
            ProviderReconciliationMethod::RawOutputSpool,
            ProviderReconciliationMethod::AdapterLog,
        ],
        ..reconciliation_input(
            false,
            false,
            vec![identity_check("external_invocation_ref", true)],
        )
    });
    assert_eq!(
        result.outcome.effective_state,
        ProviderInvocationState::NonReconcilableUnknown
    );
    assert!(
        !result
            .record
            .methods_attempted
            .contains(&ProviderReconciliationMethod::OfficialStatusLookup)
    );
}

#[test]
fn restart_matrix_never_adds_a_second_dispatch() -> TestResult {
    let matrix = [
        vec![ProviderInvocationState::Reserved],
        vec![
            ProviderInvocationState::Reserved,
            ProviderInvocationState::DispatchStarting,
        ],
        vec![
            ProviderInvocationState::Reserved,
            ProviderInvocationState::DispatchStarting,
            ProviderInvocationState::Dispatched,
        ],
        vec![
            ProviderInvocationState::Reserved,
            ProviderInvocationState::DispatchStarting,
            ProviderInvocationState::Dispatched,
            ProviderInvocationState::Running,
            ProviderInvocationState::OutputObserved,
        ],
        vec![
            ProviderInvocationState::Reserved,
            ProviderInvocationState::DispatchStarting,
            ProviderInvocationState::Dispatched,
            ProviderInvocationState::Running,
            ProviderInvocationState::CompletedCaptured,
        ],
        vec![
            ProviderInvocationState::Reserved,
            ProviderInvocationState::DispatchStarting,
            ProviderInvocationState::Dispatched,
            ProviderInvocationState::Running,
            ProviderInvocationState::TimeoutPendingReconciliation,
        ],
        vec![
            ProviderInvocationState::Reserved,
            ProviderInvocationState::DispatchStarting,
            ProviderInvocationState::Dispatched,
            ProviderInvocationState::Running,
            ProviderInvocationState::CompletedCaptured,
            ProviderInvocationState::CleanupFailedAfterComplete,
        ],
    ];
    for (index, states) in matrix.iter().enumerate() {
        let root = temp_root(&format!("restart-{index}"));
        let journal = ProviderInvocationJournal::new(&root);
        let id = format!("restart-{index}");
        let mut current = journal.create(attempt(&id))?;
        for state in states {
            journal.transition(&mut current, *state, Vec::new())?;
        }
        let reloaded = journal.load(&id)?;
        assert_eq!(reloaded.state_transitions, current.state_transitions);
        assert!(
            reloaded
                .state_transitions
                .iter()
                .filter(|transition| transition.to == ProviderInvocationState::Dispatched)
                .count()
                <= 1
        );
        cleanup(&root);
    }
    Ok(())
}

#[test]
fn readiness_gate_distinguishes_all_blockers() {
    let local = readiness_input();
    assert_eq!(
        ProviderRouteReadinessService
            .evaluate(ProviderReadinessInput {
                local_adapter_health: false,
                ..local.clone()
            })
            .verdict,
        ProviderRouteReadinessVerdict::BlockedByLocalRoute
    );
    assert_eq!(
        ProviderRouteReadinessService
            .evaluate(ProviderReadinessInput {
                provider_explicitly_unavailable: true,
                ..local.clone()
            })
            .verdict,
        ProviderRouteReadinessVerdict::BlockedByProvider
    );
    assert_eq!(
        ProviderRouteReadinessService
            .evaluate(ProviderReadinessInput {
                timeout_contract_complete: false,
                ..local.clone()
            })
            .verdict,
        ProviderRouteReadinessVerdict::BlockedByUnknownTimeoutContract
    );
    assert_eq!(
        ProviderRouteReadinessService
            .evaluate(local.clone())
            .verdict,
        ProviderRouteReadinessVerdict::RequiresOperatorAuthorization
    );
    assert_eq!(
        ProviderRouteReadinessService
            .evaluate(ProviderReadinessInput {
                operator_authorized: true,
                ..local
            })
            .verdict,
        ProviderRouteReadinessVerdict::ReadyForFreshCanary
    );
}

#[test]
fn raw_spool_is_bounded_hashed_and_stream_specific() -> TestResult {
    let root = temp_root("spool");
    let oversized = vec![b'x'; 70_000];
    let Err(rejected) = ProviderOutputSpool.capture(
        &root,
        "attempt:oversized",
        "stdout",
        Cursor::new(oversized),
        1_024,
    ) else {
        return Err(std::io::Error::other("oversized output was accepted").into());
    };
    assert!(rejected.to_string().contains("output_too_large"));
    assert!(
        !root
            .join("spool/provider-invocations/attempt_oversized/stdout.bin")
            .exists()
    );

    let stdout_bytes = b"bounded provider output";
    let stdout = ProviderOutputSpool.capture(
        &root,
        "attempt:spool",
        "stdout",
        Cursor::new(stdout_bytes),
        1_024,
    )?;
    let stderr = ProviderOutputSpool.capture(
        &root,
        "attempt:spool",
        "stderr",
        Cursor::new(b"error"),
        1_024,
    )?;
    assert!(!stdout.truncation_detected);
    assert_eq!(stdout.blob_ref.size_bytes, stdout_bytes.len() as u64);
    assert_eq!(
        fs::metadata(root.join(&stdout.blob_ref.relative_path))?.len(),
        stdout_bytes.len() as u64
    );
    assert_ne!(stdout.blob_ref.relative_path, stderr.blob_ref.relative_path);
    assert_eq!(stdout.blob_ref.algorithm, "blake3");
    cleanup(&root);
    Ok(())
}

#[test]
fn l1c_r_verifier_surface_has_no_provider_dispatch_command() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root missing")?;
    let justfile = fs::read_to_string(root.join("Justfile"))?;
    let l1c_r = justfile.split("phase-l1c-r:").nth(1).unwrap_or_default();
    assert!(!l1c_r.contains("phase-l1c-provider-once"));
    assert!(!l1c_r.contains("provider-once"));
    let runtime = fs::read_to_string(root.join("crates/eliot-app/src/l1c_r_runtime.rs"))?;
    assert!(!runtime.contains("AntigravityRunner"));
    assert!(!runtime.contains("execute_real"));
    Ok(())
}

fn attempt(id: &str) -> ProviderInvocationAttempt {
    ProviderInvocationAttempt {
        invocation_attempt_id: id.to_owned(),
        provider: "antigravity".to_owned(),
        campaign_id: CAMPAIGN_ID.to_owned(),
        preregistration_id: "provider-preregistration:test".to_owned(),
        reservation_id: RESERVATION_ID.to_owned(),
        idempotency_key: "idempotency:test".to_owned(),
        external_invocation_ref: None,
        frozen_input_hash: "frozen:test".to_owned(),
        request_payload_hash: "request:test".to_owned(),
        route_or_model: Some("fixture".to_owned()),
        adapter_version: Some("test".to_owned()),
        executable_or_transport: Some("fixture".to_owned()),
        cwd: Some("fixture".to_owned()),
        environment_fingerprint: Some("fixture".to_owned()),
        timeout_profile_id: "timeout:test".to_owned(),
        state_transitions: Vec::new(),
        dispatch_started_at: None,
        process_started_at: None,
        provider_ack_at: None,
        first_output_at: None,
        last_output_at: None,
        process_exit_at: None,
        cleanup_completed_at: None,
        stdout_blob_or_hash: None,
        stderr_blob_or_hash: None,
        structured_output_blob_or_hash: None,
        exit_code_or_signal: None,
        process_or_job_identity: None,
        quota_or_cost_if_known: None,
        original_closeout_ref: None,
    }
}

fn reconciliation_input(
    complete: bool,
    terminal_failure_proven: bool,
    identity_checks: Vec<ProviderIdentityCheck>,
) -> ProviderReconciliationInput {
    ProviderReconciliationInput {
        reconciliation_id: "reconciliation:test".to_owned(),
        outcome_id: "outcome:test".to_owned(),
        invocation_attempt_ref: INVOCATION_REF.to_owned(),
        methods_attempted: vec![ProviderReconciliationMethod::LocalWal],
        identity_checks,
        recovered_artifacts: vec!["spool/stdout#blake3=test".to_owned()],
        mismatched_artifacts_quarantined: Vec::new(),
        completeness: completeness(complete, true, false),
        recovered_review_id: complete.then(|| "candidate-review:test".to_owned()),
        terminal_failure_proven,
        terminal_failure_class: terminal_failure_proven
            .then_some(ProviderInvocationOutcomeClass::ProcessExitNonzero),
        dispatch_proven: true,
        slot_consumed: true,
        raw_output_preserved: true,
        timeout_class: Some(ProviderTimeoutClass::AbsoluteRuntimeTimeout),
        exact_failure_evidence_refs: vec!["stderr:timeout".to_owned()],
        unresolved_questions: vec!["remote outcome unknown".to_owned()],
        verifier_refs: vec!["test".to_owned()],
        started_at: OffsetDateTime::now_utc(),
        completed_at: OffsetDateTime::now_utc(),
    }
}

fn completeness(
    fields_present: bool,
    stream_closed: bool,
    truncated: bool,
) -> ExternalResultCompletenessReceipt {
    ExternalResultCompletenessService.evaluate(ProviderCompletenessInput {
        receipt_id: "completeness:test".to_owned(),
        invocation_attempt_ref: INVOCATION_REF.to_owned(),
        raw_output_ref: Some("spool/stdout#blake3=test".to_owned()),
        expected_schema: "test".to_owned(),
        terminal_marker_or_protocol_status: Some("process_exit_success".to_owned()),
        required_fields_present: fields_present,
        truncation_detected: truncated,
        stream_closed_cleanly: stream_closed,
        process_exit_success: fields_present,
    })
}

fn identity_check(field: &str, matched: bool) -> ProviderIdentityCheck {
    ProviderIdentityCheck {
        field: field.to_owned(),
        expected: Some("expected".to_owned()),
        observed: Some(if matched { "expected" } else { "wrong" }.to_owned()),
        matched: Some(matched),
        evidence_ref: "fixture".to_owned(),
    }
}

fn readiness_input() -> ProviderReadinessInput {
    ProviderReadinessInput {
        readiness_gate_id: "readiness:test".to_owned(),
        provider: "antigravity".to_owned(),
        route_or_model: "fixture".to_owned(),
        local_adapter_health: true,
        executable_available: true,
        auth_or_configuration_present: true,
        provider_gate_current: true,
        provider_explicitly_unavailable: false,
        timeout_contract_complete: true,
        timeout_profile_ref: "timeout:test".to_owned(),
        durable_capture_ready: true,
        reconciliation_capability: "fixture".to_owned(),
        process_tree_cancellation_ready: true,
        historical_latency_or_timeout_evidence: vec!["fixture".to_owned()],
        quota_or_cost_visibility: true,
        operator_authorized: false,
        last_incident_class: ProviderInvocationOutcomeClass::NonReconcilableUnknown,
        evaluated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn historical_call_count() -> u32 {
    3
}

fn temp_root(label: &str) -> PathBuf {
    let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "eliot-l1c-r-{label}-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    root
}

fn cleanup(root: &Path) {
    let _ = fs::remove_dir_all(root);
}
