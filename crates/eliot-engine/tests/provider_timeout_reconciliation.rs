#![allow(clippy::unwrap_used)]
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_engine::{
    ExternalResultCompletenessService, ProviderCompletenessInput, ProviderInvocationJournal,
    ProviderInvocationLifecycleService, ProviderOutputSpool, ProviderProcessOutcome,
    ProviderReadinessInput, ProviderReconciliationInput, ProviderReconciliationService,
    ProviderRouteReadinessService,
};
use eliot_types::{
    DescendantsAtRootExit, ExternalResultCompletenessReceipt, ProcessReapReceipt,
    ProviderIdentityCheck, ProviderInvocationAttempt, ProviderInvocationOutcomeClass,
    ProviderInvocationState, ProviderReconciliationMethod, ProviderResultCompleteness,
    ProviderRouteReadinessVerdict, ProviderTimeoutClass,
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
fn process_facts_terminalize_before_local_output_admission() -> TestResult {
    let root = temp_root("process-terminal");
    let journal = ProviderInvocationJournal::new(&root);
    let mut current = journal.create(attempt("process-terminal"))?;
    for state in [
        ProviderInvocationState::Reserved,
        ProviderInvocationState::DispatchStarting,
        ProviderInvocationState::Dispatched,
        ProviderInvocationState::Running,
    ] {
        journal.transition(&mut current, state, Vec::new())?;
    }

    let process_started_at = OffsetDateTime::UNIX_EPOCH;
    let process_exit_at = process_started_at + time::Duration::milliseconds(40);
    let cleanup_completed_at = process_exit_at + time::Duration::milliseconds(5);
    journal.record_process_terminal(
        &mut current,
        &ProviderProcessOutcome {
            exit_code: Some(0),
            stdout: b"not-yet-admitted".to_vec(),
            stderr: Vec::new(),
            stdout_total_bytes: 16,
            stderr_total_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            timeout_class: None,
            cancelled: false,
            worker_error: None,
            observed_processes: Vec::new(),
            process_started_at,
            first_output_at: Some(process_started_at + time::Duration::milliseconds(10)),
            last_output_at: Some(process_started_at + time::Duration::milliseconds(20)),
            process_exit_at: Some(process_exit_at),
            cleanup_completed_at,
            reap_receipt: complete_reap_receipt(),
        },
    )?;

    let reloaded = journal.load("process-terminal")?;
    assert_eq!(
        reloaded
            .state_transitions
            .last()
            .map(|transition| transition.to),
        Some(ProviderInvocationState::ProcessTerminal)
    );
    assert_eq!(reloaded.process_exit_at, Some(process_exit_at));
    assert_eq!(reloaded.cleanup_completed_at, Some(cleanup_completed_at));
    assert!(
        reloaded
            .process_reap_receipt
            .as_ref()
            .is_some_and(ProcessReapReceipt::proves_complete_reap)
    );
    assert!(reloaded.stdout_blob_or_hash.is_none());
    assert!(reloaded.stderr_blob_or_hash.is_none());
    cleanup(&root);
    Ok(())
}

#[test]
fn legacy_attempt_without_route_policy_remains_loadable() -> TestResult {
    let root = temp_root("legacy-load");
    let path = root.join("runtime/provider-invocations/legacy-load.json");
    fs::create_dir_all(path.parent().ok_or("legacy attempt parent missing")?)?;
    let mut value = serde_json::to_value(attempt("legacy-load"))?;
    let object = value
        .as_object_mut()
        .ok_or("attempt did not serialize as an object")?;
    object.remove("provider_route_policy");
    object.remove("process_reap_receipt");
    object.remove("process_timed_out");
    object.remove("process_cancelled");
    object.remove("process_worker_error");
    object.remove("stdout_total_bytes");
    object.remove("stderr_total_bytes");
    object.remove("stdout_truncated");
    object.remove("stderr_truncated");
    fs::write(&path, serde_json::to_vec_pretty(&value)?)?;

    let loaded = ProviderInvocationJournal::new(&root).load("legacy-load")?;
    assert!(loaded.provider_route_policy.is_none());
    assert!(loaded.process_reap_receipt.is_none());
    cleanup(&root);
    Ok(())
}

#[test]
fn post_dispatch_runner_error_never_leaves_running() -> TestResult {
    let root = temp_root("post-dispatch-error");
    let journal = ProviderInvocationJournal::new(&root);
    let mut current = journal.create(attempt("post-dispatch-error"))?;
    for state in [
        ProviderInvocationState::Reserved,
        ProviderInvocationState::DispatchStarting,
        ProviderInvocationState::Dispatched,
        ProviderInvocationState::Running,
    ] {
        journal.transition(&mut current, state, Vec::new())?;
    }
    journal
        .record_post_dispatch_failure(&mut current, vec!["supervisor_error:fixture".to_owned()])?;
    assert_eq!(
        current
            .state_transitions
            .last()
            .map(|transition| transition.to),
        Some(ProviderInvocationState::TimeoutPendingReconciliation)
    );
    assert!(current.state_transitions.last().is_some_and(|transition| {
        transition
            .evidence_refs
            .contains(&"provider_redispatch_forbidden:true".to_owned())
    }));
    cleanup(&root);
    Ok(())
}

#[test]
fn missing_root_pid_is_recorded_as_unknown_not_zero() -> TestResult {
    let root = temp_root("unknown-pid");
    let journal = ProviderInvocationJournal::new(&root);
    let mut current = journal.create(attempt("unknown-pid"))?;
    for state in [
        ProviderInvocationState::Reserved,
        ProviderInvocationState::DispatchStarting,
        ProviderInvocationState::Dispatched,
        ProviderInvocationState::Running,
    ] {
        journal.transition(&mut current, state, Vec::new())?;
    }
    let mut outcome = terminal_process_outcome();
    outcome.reap_receipt.root_pid = None;
    journal.record_process_terminal(&mut current, &outcome)?;
    let identity = current
        .process_or_job_identity
        .as_deref()
        .unwrap_or_default();
    assert!(identity.contains("pid:unknown"));
    assert!(!identity.contains("pid:0"));
    cleanup(&root);
    Ok(())
}

#[test]
fn double_persistence_failure_preserves_running_and_forbids_redispatch() -> TestResult {
    let root = temp_root("double-persist-failure");
    let journal = ProviderInvocationJournal::new(&root);
    let mut current = journal.create(attempt("double-persist-failure"))?;
    for state in [
        ProviderInvocationState::Reserved,
        ProviderInvocationState::DispatchStarting,
        ProviderInvocationState::Dispatched,
        ProviderInvocationState::Running,
    ] {
        journal.transition(&mut current, state, Vec::new())?;
    }
    let attempts = root.join("runtime/provider-invocations");
    fs::remove_dir_all(&attempts)?;
    fs::write(&attempts, b"block journal directory")?;
    let reconciliations = root.join("runtime/provider-invocation-reconciliation");
    fs::write(&reconciliations, b"block reconciliation directory")?;

    let Err(error) = journal.record_post_dispatch_failure(&mut current, vec!["fixture".to_owned()])
    else {
        return Err(std::io::Error::other("both persistence paths unexpectedly succeeded").into());
    };
    let message = error.to_string();
    assert!(message.contains("sidecar also failed"));
    assert!(message.contains("provider redispatch is forbidden"));
    assert_eq!(
        current
            .state_transitions
            .last()
            .map(|transition| transition.to),
        Some(ProviderInvocationState::Running)
    );
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
            ProviderInvocationState::ProcessTerminal,
            ProviderInvocationState::OutputObserved,
        ],
        vec![
            ProviderInvocationState::Reserved,
            ProviderInvocationState::DispatchStarting,
            ProviderInvocationState::Dispatched,
            ProviderInvocationState::Running,
            ProviderInvocationState::ProcessTerminal,
            ProviderInvocationState::CompletedCaptured,
        ],
        vec![
            ProviderInvocationState::Reserved,
            ProviderInvocationState::DispatchStarting,
            ProviderInvocationState::Dispatched,
            ProviderInvocationState::Running,
            ProviderInvocationState::ProcessTerminal,
            ProviderInvocationState::TimeoutPendingReconciliation,
        ],
        vec![
            ProviderInvocationState::Reserved,
            ProviderInvocationState::DispatchStarting,
            ProviderInvocationState::Dispatched,
            ProviderInvocationState::Running,
            ProviderInvocationState::ProcessTerminal,
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
fn readiness_gate_does_not_infer_live_readiness_from_installation() {
    let gate = ProviderRouteReadinessService.evaluate(ProviderReadinessInput {
        provider_authenticated: false,
        structured_output_ready: false,
        console_headless_ready: false,
        last_successful_smoke_ref: None,
        operator_authorized: true,
        ..readiness_input()
    });
    assert_eq!(
        gate.verdict,
        ProviderRouteReadinessVerdict::BlockedByLocalRoute
    );
    assert!(!gate.provider_authenticated);
    assert!(!gate.structured_output_ready);
    assert!(!gate.console_headless_ready);
    assert!(gate.last_successful_smoke_ref.is_none());
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
fn provider_reconciliation_surface_has_no_provider_dispatch_command() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root missing")?;
    let justfile = fs::read_to_string(root.join("Justfile"))?;
    let reconciliation = justfile
        .split("provider-reconciliation:")
        .nth(1)
        .unwrap_or_default();
    assert!(!reconciliation.contains("provider-budget-provider-once"));
    assert!(!reconciliation.contains("provider-once"));
    let runtime = fs::read_to_string(root.join("crates/eliot-app/src/provider_budget_runtime.rs"))?;
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
        provider_route_policy: Some(eliot_types::ProviderRoutePolicyBinding {
            policy_id: "policy:test".to_owned(),
            policy_hash_blake3: "0".repeat(64),
        }),
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
        timeout_class: None,
        process_reap_receipt: None,
        process_timed_out: None,
        process_cancelled: None,
        process_worker_error: None,
        stdout_total_bytes: None,
        stderr_total_bytes: None,
        stdout_truncated: None,
        stderr_truncated: None,
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
        installed: true,
        provider_authenticated: true,
        exact_model_selectable: true,
        mcp_config_valid: true,
        mcp_process_started: true,
        mcp_initialized: true,
        required_tools_visible: true,
        structured_output_ready: true,
        console_headless_ready: true,
        last_successful_smoke_ref: Some("provider-smoke:fixture".to_owned()),
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

fn complete_reap_receipt() -> ProcessReapReceipt {
    ProcessReapReceipt {
        operation_id: "provider-process-terminal-test".to_owned(),
        generation: 1,
        job_object_name: "eliot-provider-test-job".to_owned(),
        root_pid: Some(42),
        process_count_before: 1,
        process_count_after: 0,
        graceful_attempted: true,
        forced_termination: false,
        stdout_closed: true,
        stderr_closed: true,
        all_tasks_joined: true,
        elapsed_ms: 45,
        terminal_error_codes: Vec::new(),
        descendants_at_root_exit: DescendantsAtRootExit::captured(42, Some(0), 45, Vec::new())
            .unwrap(),
    }
}

fn terminal_process_outcome() -> ProviderProcessOutcome {
    let process_started_at = OffsetDateTime::UNIX_EPOCH;
    let process_exit_at = process_started_at + time::Duration::milliseconds(40);
    ProviderProcessOutcome {
        exit_code: Some(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_total_bytes: 0,
        stderr_total_bytes: 0,
        stdout_truncated: false,
        stderr_truncated: false,
        timed_out: false,
        timeout_class: None,
        cancelled: false,
        worker_error: None,
        observed_processes: Vec::new(),
        process_started_at,
        first_output_at: None,
        last_output_at: None,
        process_exit_at: Some(process_exit_at),
        cleanup_completed_at: process_exit_at + time::Duration::milliseconds(5),
        reap_receipt: complete_reap_receipt(),
    }
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
