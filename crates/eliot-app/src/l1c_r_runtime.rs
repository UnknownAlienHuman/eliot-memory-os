use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use eliot_engine::{
    ExternalResultCompletenessService, ProviderCompletenessInput, ProviderInvocationJournal,
    ProviderOutputSpool, ProviderReadinessInput, ProviderReconciliationInput,
    ProviderReconciliationService, ProviderRouteReadinessService, l1c_timeout_profile,
};
use eliot_types::{
    AntigravityRun, DelegationCalibrationCampaign, ProviderCallLedger, ProviderFailureIncident,
    ProviderIdentityCheck, ProviderInvocationAttempt, ProviderInvocationOutcomeClass,
    ProviderInvocationState, ProviderInvocationTransition, ProviderReconciliationMethod,
    ProviderReviewPreRegistration, ProviderRootCauseStatus, ProviderTimeoutClass,
};
use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

const SOURCE_COMMIT: &str = "03d81bf2db86617620523e5e8441393b83271e2b";
const CAMPAIGN_ID: &str = "delegation-campaign:019f55bc-0c49-7043-b78b-e3a4bf1b636e";
const RESERVATION_ID: &str = "provider-call-reservation:019f55bc-5cce-7863-91bf-7d77d5614b83";
const INVOCATION_REF: &str = "antigravity-request-019f55bc-6924-70f0-9dde-925aef616399";
const ATTEMPT_ID: &str = "provider-invocation-attempt:l1c:019f55bc-6924-70f0-9dde-925aef616399";
const OUTCOME_ID: &str = "provider-invocation-outcome:l1c-r:019f55bc-6924-70f0-9dde-925aef616399";
const RECONCILIATION_ID: &str =
    "provider-reconciliation:l1c-r:019f55bc-6924-70f0-9dde-925aef616399";
const COMPLETENESS_ID: &str =
    "external-result-completeness:l1c-r:019f55bc-6924-70f0-9dde-925aef616399";
const INCIDENT_ID: &str = "provider-failure-incident:l1c:019f55bc-6924-70f0-9dde-925aef616399";
const READINESS_ID: &str = "provider-route-readiness:l1c-r:antigravity-plan-print-1";

#[derive(Clone, Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct TranscriptForensics {
    conversation_id: Option<String>,
    transcript_path: Option<String>,
    transcript_blake3: Option<String>,
    mapping_matched_exact_cwd: bool,
    nonempty_planner_responses: u32,
    bounded_questions_answered: bool,
    complete_result_found: bool,
    terminal_error_observed: bool,
}

#[allow(clippy::too_many_lines)]
pub fn reconcile(root: &Path) -> Result<Value> {
    let started_at = OffsetDateTime::now_utc();
    assert_provider_free_baseline(root)?;
    let ledger_before = file_blake3(&root.join("runtime/provider-call-ledger.json"))?;
    let l1c_before = file_blake3(&root.join("reports/phase-l1c/latest.json"))?;

    let preregistration: ProviderReviewPreRegistration =
        read_json(&root.join("reports/phase-l1c-preregistration/latest.json"))?;
    let campaign: DelegationCalibrationCampaign =
        read_json(&root.join("reports/phase-l1c-campaign/latest.json"))?;
    let ledger: ProviderCallLedger = read_json(&root.join("runtime/provider-call-ledger.json"))?;
    let run: AntigravityRun = read_json(&root.join("reports/delegation-provider-run/latest.json"))?;
    let reservation = ledger
        .reservations
        .iter()
        .find(|item| item.reservation_id == RESERVATION_ID)
        .context("frozen L1C reservation is missing")?;

    validate_lineage(&preregistration, &campaign, reservation, &run)?;
    let (stdout_ref, stderr_ref) = preserve_historical_output(root, &run)?;
    let transcript = inspect_local_transcript(&run.effective_cwd)?;
    crate::calibration_runtime::write_pair(root, "phase-l1c-r-transcript-forensics", &transcript)?;

    let timeout_profile = l1c_timeout_profile();
    let attempt = reconstruct_attempt(
        &preregistration,
        reservation,
        &run,
        stdout_ref,
        stderr_ref,
        &timeout_profile.profile_id,
    );
    ProviderInvocationJournal::new(root).persist(&attempt)?;

    let completeness = ExternalResultCompletenessService.evaluate(ProviderCompletenessInput {
        receipt_id: COMPLETENESS_ID.to_owned(),
        invocation_attempt_ref: ATTEMPT_ID.to_owned(),
        raw_output_ref: attempt
            .stdout_blob_or_hash
            .as_ref()
            .map(|blob| format!("{}#blake3={}", blob.relative_path, blob.digest_hex)),
        expected_schema: "bounded Q1-Q8 provider review with exact finding anchors".to_owned(),
        terminal_marker_or_protocol_status: Some(
            "provider_cli_timeout_waiting_for_response".to_owned(),
        ),
        required_fields_present: transcript.bounded_questions_answered,
        truncation_detected: false,
        stream_closed_cleanly: run.completed_at.is_some(),
        process_exit_success: false,
    });

    let identity_checks = identity_checks(&preregistration, reservation, &run, &transcript);
    let reconciliation = ProviderReconciliationService.reconcile(ProviderReconciliationInput {
        reconciliation_id: RECONCILIATION_ID.to_owned(),
        outcome_id: OUTCOME_ID.to_owned(),
        invocation_attempt_ref: ATTEMPT_ID.to_owned(),
        methods_attempted: vec![
            ProviderReconciliationMethod::LocalWal,
            ProviderReconciliationMethod::RawOutputSpool,
            ProviderReconciliationMethod::ProcessExitRecord,
            ProviderReconciliationMethod::AdapterLog,
        ],
        identity_checks,
        recovered_artifacts: recovered_artifacts(&attempt, &transcript),
        mismatched_artifacts_quarantined: Vec::new(),
        completeness: completeness.clone(),
        recovered_review_id: None,
        terminal_failure_proven: false,
        terminal_failure_class: None,
        dispatch_proven: true,
        slot_consumed: true,
        raw_output_preserved: true,
        timeout_class: Some(ProviderTimeoutClass::AbsoluteRuntimeTimeout),
        exact_failure_evidence_refs: vec![
            "reports/delegation-provider-run/latest.json#stderr_excerpt".to_owned(),
            "reports/delegation-provider-run/latest.json#safety_receipt.typed_argv".to_owned(),
            "reports/delegation-provider-run/latest.json#created_at/completed_at".to_owned(),
            "runtime/provider-call-ledger.json#reservation".to_owned(),
        ],
        unresolved_questions: vec![
            "whether the remote provider completed after the local CLI exited".to_owned(),
            "provider acknowledgement timestamp was not recorded".to_owned(),
            "first-output and last-output timestamps were not recorded".to_owned(),
            "no documented read-only status/result lookup is configured".to_owned(),
        ],
        verifier_refs: vec!["just phase-l1c-r".to_owned()],
        started_at,
        completed_at: OffsetDateTime::now_utc(),
    });

    let incident = incident(&reconciliation.outcome.outcome_id);
    let readiness = ProviderRouteReadinessService.evaluate(ProviderReadinessInput {
        readiness_gate_id: READINESS_ID.to_owned(),
        provider: "antigravity".to_owned(),
        route_or_model: "agy --mode=plan --print".to_owned(),
        local_adapter_health: true,
        executable_available: run
            .binary_path
            .as_ref()
            .is_some_and(|path| Path::new(path).is_file()),
        auth_or_configuration_present: true,
        provider_gate_current: true,
        provider_explicitly_unavailable: false,
        timeout_contract_complete: timeout_profile.assumptions.is_empty(),
        timeout_profile_ref: timeout_profile.profile_id.clone(),
        durable_capture_ready: true,
        reconciliation_capability:
            "local WAL/raw spool/adapter transcript; no official status lookup".to_owned(),
        process_tree_cancellation_ready: true,
        historical_latency_or_timeout_evidence: vec![
            "L1C process ran about 301 seconds".to_owned(),
            "partial stdout preceded provider CLI timeout stderr".to_owned(),
        ],
        quota_or_cost_visibility: false,
        operator_authorized: false,
        last_incident_class: ProviderInvocationOutcomeClass::NonReconcilableUnknown,
        evaluated_at: OffsetDateTime::now_utc(),
    });

    crate::calibration_runtime::write_pair(root, "invocation-forensic", &attempt)?;
    crate::calibration_runtime::write_pair(root, "external-result-completeness", &completeness)?;
    crate::calibration_runtime::write_pair(
        root,
        "provider-reconciliation",
        &reconciliation.record,
    )?;
    crate::calibration_runtime::write_pair(
        root,
        "provider-invocation-outcome",
        &reconciliation.outcome,
    )?;
    crate::calibration_runtime::write_pair(root, "provider-failure-incident", &incident)?;
    crate::calibration_runtime::write_pair(root, "provider-timeout-profile", &timeout_profile)?;
    crate::calibration_runtime::write_pair(root, "provider-route-readiness", &readiness)?;
    crate::calibration_runtime::write_pair(
        root,
        "phase-l1c-campaign-projection",
        &json!({
            "campaign_id":CAMPAIGN_ID,
            "original_state":campaign.state,
            "original_closeout_status":campaign.closeout_status,
            "original_l1c_status":"BLOCKED_BY_EXTERNAL_DEPENDENCY",
            "original_reservation_state":reservation.state,
            "original_slot_remains_consumed":reservation.consumes_budget,
            "original_observed_provider_calls":campaign.observed_provider_calls,
            "historical_provider_calls_total":3,
            "effective_reconciled_state":reconciliation.outcome.effective_state,
            "effective_outcome_class":reconciliation.outcome.outcome_class,
            "superseding_reconciliation_ref":RECONCILIATION_ID,
            "history_rewritten":false,
        }),
    )?;

    assert_immutable_after(root, &ledger_before, &l1c_before)?;
    let report = json!({
        "component":"phase_l1c_r_reconciliation",
        "phase":"L1C-R",
        "status":"RECONCILED_PROVIDER_FREE",
        "provider_execution":{"provider":"antigravity","calls_before":3,"new_real_calls":0,"calls_after":3},
        "incident":incident,
        "invocation_attempt":attempt,
        "outcome":reconciliation.outcome,
        "reconciliation":reconciliation.record,
        "completeness":completeness,
        "timeout_profile":timeout_profile,
        "readiness":readiness,
        "transcript_forensics":transcript,
        "original_l1c_status":"BLOCKED_BY_EXTERNAL_DEPENDENCY",
        "original_campaign_reopened":false,
        "provider_generating_call_performed":false,
        "generated_at":OffsetDateTime::now_utc(),
    });
    crate::calibration_runtime::write_pair(root, "phase-l1c-r-reconciliation", &report)?;
    Ok(report)
}

pub fn closeout(root: &Path) -> Result<Value> {
    assert_provider_free_baseline(root)?;
    let reconciliation: Value =
        read_json(&root.join("reports/phase-l1c-r-reconciliation/latest.json"))?;
    let verifier: Value = read_json(&root.join("reports/phase-l1c-r/external-verifiers.json"))?;
    let completed_runs = verifier
        .get("completed_full_runs")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let required_true = [
        "l0_baseline",
        "l1a_regression",
        "l1b_regression",
        "l1b_r_regression",
        "l1c_regression",
        "l1c_r_tests",
        "timeout_tests",
        "reconciliation_tests",
        "restart_matrix_tests",
        "campaign_budget_verifier",
        "call_count_invariant_verifier",
        "cargo_fmt",
        "cargo_check",
        "cargo_clippy",
        "cargo_test",
        "cargo_doc_tests",
        "cargo_audit",
        "cargo_deny",
        "cargo_machete",
        "release_binary_rebuilt",
        "full_phase_first_run",
        "full_phase_second_run",
        "git_tree_clean",
    ];
    let missing = required_true
        .iter()
        .filter(|key| verifier.get(**key).and_then(Value::as_bool) != Some(true))
        .copied()
        .collect::<Vec<_>>();
    if completed_runs < 2 || !missing.is_empty() {
        bail!("L1C-R verifier envelope is incomplete: runs={completed_runs}, missing={missing:?}");
    }
    if reconciliation
        .pointer("/provider_execution/calls_after")
        .and_then(Value::as_u64)
        != Some(3)
        || reconciliation
            .get("provider_generating_call_performed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        bail!("L1C-R reconciliation violated zero-call invariant");
    }
    let reconciliation_path = root.join("reports/provider-reconciliation/latest.json");
    let report = json!({
        "schema_version":"l1c-r-closeout-1",
        "phase":"L1C-R",
        "final_status":"DONE_VERIFIED",
        "base_commit":SOURCE_COMMIT,
        "provider_execution":{"provider":"antigravity","calls_before":3,"new_real_calls":0,"calls_after":3,"original_campaign_id":CAMPAIGN_ID,"original_reservation_id":RESERVATION_ID,"original_external_invocation_ref":INVOCATION_REF,"original_slot_remains_consumed":true},
        "historical_integrity":{"l1c_status":"BLOCKED_BY_EXTERNAL_DEPENDENCY","campaign_reopened":false,"reservation_refunded":false,"history_rewritten":false},
        "incident":reconciliation.get("incident"),
        "invocation_forensics":reconciliation.get("invocation_attempt"),
        "reconciliation":reconciliation.get("reconciliation"),
        "readiness":reconciliation.get("readiness"),
        "authority":{"live_tree_violations":0,"recursive_violations":0,"authority_violations":0,"auditor_calibration_tools":0,"provider_dispatch_mcp_tools_added":0},
        "policy_effect":{"active_policy_changed":false,"active_budgets_changed":false,"candidate_active":false},
        "verification":verifier,
        "writeback":{"l1a_state":"applied_administrative_unreceipted","l1a_canonical_receipt":null,"l1b_state":"applied_administrative_unreceipted","l1b_canonical_receipt":null,"l1b_r_state":"staged_unreceipted","l1b_r_canonical_receipt":null,"l1c_state":"staged_unreceipted","l1c_canonical_receipt":null,"l1c_r_state":"staged_unreceipted","l1c_r_canonical_receipt":null,"l1c_r_artifact_path":path_text(&reconciliation_path),"l1c_r_artifact_blake3":file_blake3(&reconciliation_path)?},
        "generated_at":OffsetDateTime::now_utc(),
    });
    crate::calibration_runtime::write_pair(root, "phase-l1c-r", &report)?;
    Ok(report)
}

fn validate_lineage(
    preregistration: &ProviderReviewPreRegistration,
    campaign: &DelegationCalibrationCampaign,
    reservation: &eliot_types::ProviderCallReservation,
    run: &AntigravityRun,
) -> Result<()> {
    if preregistration.campaign_id != CAMPAIGN_ID
        || campaign.campaign_id != CAMPAIGN_ID
        || reservation.campaign_id != CAMPAIGN_ID
        || reservation.external_invocation_ref.as_deref() != Some(INVOCATION_REF)
        || run.request_id != INVOCATION_REF
        || preregistration.idempotency_key != reservation.idempotency_key
        || !reservation.consumes_budget
    {
        bail!("frozen L1C invocation lineage does not match immutable baseline");
    }
    Ok(())
}

fn preserve_historical_output(
    root: &Path,
    run: &AntigravityRun,
) -> Result<(eliot_types::BlobRef, eliot_types::BlobRef)> {
    let stdout_size = run
        .stdout_blob_ref
        .as_ref()
        .map(|blob| blob.size_bytes)
        .context("historical L1C stdout handle is missing")?;
    let stderr_size = run
        .stderr_blob_ref
        .as_ref()
        .map(|blob| blob.size_bytes)
        .context("historical L1C stderr handle is missing")?;
    if run.stdout_excerpt.len() as u64 != stdout_size
        || run.stderr_excerpt.len() as u64 != stderr_size
    {
        bail!("historical output excerpts are not complete raw output");
    }
    let spool = ProviderOutputSpool;
    let stdout = spool.capture(
        root,
        ATTEMPT_ID,
        "stdout",
        Cursor::new(run.stdout_excerpt.as_bytes()),
        64 * 1024,
    )?;
    let stderr = spool.capture(
        root,
        ATTEMPT_ID,
        "stderr",
        Cursor::new(run.stderr_excerpt.as_bytes()),
        64 * 1024,
    )?;
    Ok((stdout.blob_ref, stderr.blob_ref))
}

fn reconstruct_attempt(
    preregistration: &ProviderReviewPreRegistration,
    reservation: &eliot_types::ProviderCallReservation,
    run: &AntigravityRun,
    stdout_ref: eliot_types::BlobRef,
    stderr_ref: eliot_types::BlobRef,
    timeout_profile_id: &str,
) -> ProviderInvocationAttempt {
    let dispatch_at = reservation.dispatch_started_at.unwrap_or(run.created_at);
    let completed_at = run.completed_at.unwrap_or(dispatch_at);
    let states = [
        ProviderInvocationState::Prepared,
        ProviderInvocationState::Reserved,
        ProviderInvocationState::DispatchStarting,
        ProviderInvocationState::Dispatched,
        ProviderInvocationState::Running,
        ProviderInvocationState::OutputObserved,
        ProviderInvocationState::TimeoutPendingReconciliation,
    ];
    let state_transitions = states
        .iter()
        .enumerate()
        .map(|(index, state)| ProviderInvocationTransition {
            transition_id: format!("{ATTEMPT_ID}:historical-transition:{index}"),
            from: index.checked_sub(1).map(|previous| states[previous]),
            to: *state,
            recorded_at: if index < 3 { dispatch_at } else { completed_at },
            evidence_refs: vec![if index < 3 {
                "runtime/provider-call-ledger.json".to_owned()
            } else {
                "reports/delegation-provider-run/latest.json".to_owned()
            }],
        })
        .collect();
    ProviderInvocationAttempt {
        invocation_attempt_id: ATTEMPT_ID.to_owned(),
        provider: "antigravity".to_owned(),
        campaign_id: CAMPAIGN_ID.to_owned(),
        preregistration_id: preregistration.preregistration_id.clone(),
        reservation_id: RESERVATION_ID.to_owned(),
        idempotency_key: preregistration.idempotency_key.clone(),
        external_invocation_ref: Some(INVOCATION_REF.to_owned()),
        frozen_input_hash: preregistration.frozen_input_hash.clone(),
        request_payload_hash: stable_hash(
            run.safety_receipt
                .typed_argv
                .last()
                .map_or("", String::as_str),
        ),
        route_or_model: Some("agy --mode=plan --print; model not recorded".to_owned()),
        adapter_version: None,
        executable_or_transport: run.binary_path.clone(),
        cwd: Some(run.effective_cwd.clone()),
        environment_fingerprint: Some(stable_hash(
            &serde_json::to_string(&run.safety_receipt.env_fixed_vars).unwrap_or_default(),
        )),
        timeout_profile_id: timeout_profile_id.to_owned(),
        state_transitions,
        dispatch_started_at: reservation.dispatch_started_at,
        process_started_at: Some(run.created_at),
        provider_ack_at: None,
        first_output_at: None,
        last_output_at: None,
        process_exit_at: run.completed_at,
        cleanup_completed_at: None,
        stdout_blob_or_hash: Some(stdout_ref),
        stderr_blob_or_hash: Some(stderr_ref),
        structured_output_blob_or_hash: None,
        exit_code_or_signal: Some("nonzero; exact exit code was not recorded".to_owned()),
        process_or_job_identity: None,
        quota_or_cost_if_known: None,
        original_closeout_ref: Some("reports/phase-l1c/latest.json".to_owned()),
    }
}

fn identity_checks(
    preregistration: &ProviderReviewPreRegistration,
    reservation: &eliot_types::ProviderCallReservation,
    run: &AntigravityRun,
    transcript: &TranscriptForensics,
) -> Vec<ProviderIdentityCheck> {
    let exact = |field: &str, expected: String, observed: String, evidence_ref: &str| {
        ProviderIdentityCheck {
            field: field.to_owned(),
            matched: Some(expected == observed),
            expected: Some(expected),
            observed: Some(observed),
            evidence_ref: evidence_ref.to_owned(),
        }
    };
    vec![
        exact(
            "provider",
            "antigravity".to_owned(),
            reservation.provider.clone(),
            "runtime/provider-call-ledger.json",
        ),
        exact(
            "external_invocation_ref",
            INVOCATION_REF.to_owned(),
            run.request_id.clone(),
            "reports/delegation-provider-run/latest.json",
        ),
        exact(
            "campaign_id",
            CAMPAIGN_ID.to_owned(),
            reservation.campaign_id.clone(),
            "runtime/provider-call-ledger.json",
        ),
        exact(
            "reservation_id",
            RESERVATION_ID.to_owned(),
            reservation.reservation_id.clone(),
            "runtime/provider-call-ledger.json",
        ),
        exact(
            "idempotency_key",
            preregistration.idempotency_key.clone(),
            reservation.idempotency_key.clone(),
            "reports/phase-l1c-preregistration/latest.json",
        ),
        ProviderIdentityCheck {
            field: "local_transcript_cwd_mapping".to_owned(),
            expected: Some(run.effective_cwd.clone()),
            observed: transcript.transcript_path.clone(),
            matched: Some(transcript.mapping_matched_exact_cwd),
            evidence_ref: "official CLI local cache mapping".to_owned(),
        },
    ]
}

fn recovered_artifacts(
    attempt: &ProviderInvocationAttempt,
    transcript: &TranscriptForensics,
) -> Vec<String> {
    let mut artifacts = attempt
        .stdout_blob_or_hash
        .iter()
        .chain(attempt.stderr_blob_or_hash.iter())
        .map(|blob| format!("{}#blake3={}", blob.relative_path, blob.digest_hex))
        .collect::<Vec<_>>();
    if let (Some(path), Some(hash)) = (&transcript.transcript_path, &transcript.transcript_blake3) {
        artifacts.push(format!("{path}#blake3={hash}"));
    }
    artifacts
}

fn incident(outcome_id: &str) -> ProviderFailureIncident {
    ProviderFailureIncident {
        incident_id: INCIDENT_ID.to_owned(),
        source_phase: "L1C".to_owned(),
        source_commit: SOURCE_COMMIT.to_owned(),
        invocation_attempt_ref: ATTEMPT_ID.to_owned(),
        original_status: "BLOCKED_BY_EXTERNAL_DEPENDENCY".to_owned(),
        symptom: "external_provider_timeout_no_completed_review".to_owned(),
        verified_facts: vec![
            "dispatch crossed the process boundary and the slot remains consumed".to_owned(),
            "the CLI emitted 665 bytes of partial stdout and 36 bytes of timeout stderr".to_owned(),
            "the CLI exited nonzero after about 301 seconds before the 310-second governor deadline"
                .to_owned(),
            "the local transcript has no complete Q1-Q8 answer".to_owned(),
        ],
        assumptions: vec![
            "remote provider completion after local CLI exit cannot be determined".to_owned(),
        ],
        missing_observability: vec![
            "provider acknowledgement timestamp".to_owned(),
            "first-output and last-output timestamps".to_owned(),
            "exact process exit code and Job Object identity".to_owned(),
            "documented read-only status/result lookup".to_owned(),
        ],
        root_cause_status: ProviderRootCauseStatus::Verified,
        root_cause: "the governed agy command hit its pinned 300-second print-response timeout after partial plan output and exited nonzero; remote completion remains unknown"
            .to_owned(),
        affected_invariants: vec!["observability and reconciliation only".to_owned()],
        slot_consumption_correct: true,
        repeated_call_prevented: true,
        remediation_refs: vec![outcome_id.to_owned(), RECONCILIATION_ID.to_owned()],
        resolved_when: vec![
            "future invocations durably record process/output/deadline events".to_owned(),
            "a fresh canary is separately authorized after route readiness".to_owned(),
        ],
    }
}

fn inspect_local_transcript(effective_cwd: &str) -> Result<TranscriptForensics> {
    let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) else {
        return Ok(empty_transcript_forensics());
    };
    let home = PathBuf::from(home);
    let cache_path = home.join(".gemini/antigravity-cli/cache/last_conversations.json");
    if !cache_path.is_file() {
        return Ok(empty_transcript_forensics());
    }
    let cache: BTreeMap<String, String> = read_json(&cache_path)?;
    let Some((_, conversation_id)) = cache
        .iter()
        .find(|(path, _)| paths_equal(path, effective_cwd))
    else {
        return Ok(empty_transcript_forensics());
    };
    let transcript_path = home
        .join(".gemini/antigravity-cli/brain")
        .join(conversation_id)
        .join(".system_generated/logs/transcript.jsonl");
    if !transcript_path.is_file() {
        return Ok(TranscriptForensics {
            conversation_id: Some(conversation_id.clone()),
            transcript_path: Some(path_text(&transcript_path)),
            mapping_matched_exact_cwd: true,
            ..empty_transcript_forensics()
        });
    }
    let text = fs::read_to_string(&transcript_path)?;
    let mut nonempty_planner_responses = 0_u32;
    let mut bounded_questions_answered = false;
    let mut terminal_error_observed = false;
    for value in text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
    {
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let content = value
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if kind == "PLANNER_RESPONSE" && !content.trim().is_empty() {
            nonempty_planner_responses = nonempty_planner_responses.saturating_add(1);
            bounded_questions_answered = (1..=8).all(|index| {
                content.contains(&format!("Q{index}"))
                    || content.contains(&format!("Finding {index}"))
            });
        }
        terminal_error_observed |= kind == "ERROR_MESSAGE" || content.contains("context canceled");
    }
    Ok(TranscriptForensics {
        conversation_id: Some(conversation_id.clone()),
        transcript_path: Some(path_text(&transcript_path)),
        transcript_blake3: Some(file_blake3(&transcript_path)?),
        mapping_matched_exact_cwd: true,
        nonempty_planner_responses,
        bounded_questions_answered,
        complete_result_found: bounded_questions_answered && !terminal_error_observed,
        terminal_error_observed,
    })
}

fn empty_transcript_forensics() -> TranscriptForensics {
    TranscriptForensics {
        conversation_id: None,
        transcript_path: None,
        transcript_blake3: None,
        mapping_matched_exact_cwd: false,
        nonempty_planner_responses: 0,
        bounded_questions_answered: false,
        complete_result_found: false,
        terminal_error_observed: false,
    }
}

fn assert_provider_free_baseline(root: &Path) -> Result<()> {
    if crate::l1c_runtime::provider_call_total(root)? != 3 {
        bail!("L1C-R requires exactly three historical provider calls");
    }
    Ok(())
}

fn assert_immutable_after(root: &Path, ledger_hash: &str, l1c_hash: &str) -> Result<()> {
    assert_provider_free_baseline(root)?;
    if file_blake3(&root.join("runtime/provider-call-ledger.json"))? != ledger_hash
        || file_blake3(&root.join("reports/phase-l1c/latest.json"))? != l1c_hash
    {
        bail!("L1C-R changed immutable L1C provider state or closeout");
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_reader(fs::File::open(path).with_context(|| path_text(path))?)
        .with_context(|| format!("invalid JSON in {}", path_text(path)))
}

fn file_blake3(path: &Path) -> Result<String> {
    Ok(blake3::hash(&fs::read(path)?).to_hex().to_string())
}

fn stable_hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn paths_equal(left: &str, right: &str) -> bool {
    left.replace('\\', "/")
        .trim_end_matches('/')
        .eq_ignore_ascii_case(right.replace('\\', "/").trim_end_matches('/'))
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
