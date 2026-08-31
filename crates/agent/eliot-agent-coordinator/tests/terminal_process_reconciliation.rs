use std::error::Error;

use eliot_agent_api::AttemptId;
use eliot_agent_coordinator::{
    AttemptAlertCode, AttemptAutomationDisposition, AttemptEffectObservation,
    AttemptTelemetryInput, AttemptTerminalReconciliation, CoordinatedAttemptState,
    ProcessObservation, QuotaDisposition, QuotaObservation, project_attempt_health,
};

const NOW: u64 = 10_000;

type TestResult = Result<(), Box<dyn Error>>;

fn quota() -> QuotaObservation {
    QuotaObservation {
        disposition: QuotaDisposition::Available,
        source: "test-quota".to_owned(),
        receipt_ref: "quota-receipt".to_owned(),
        observed_at_unix_ms: NOW - 100,
        expires_at_unix_ms: NOW + 100,
        reset_at_unix_ms: Some(NOW + 1_000),
        remaining_microunits: Some(1),
    }
}

fn telemetry(
    state: CoordinatedAttemptState,
    process: ProcessObservation,
) -> Result<AttemptTelemetryInput, Box<dyn Error>> {
    Ok(AttemptTelemetryInput {
        attempt_id: AttemptId::new("attempt-terminal-process")?,
        state,
        observed_at_unix_ms: NOW,
        started_at_unix_ms: NOW - 1_000,
        last_heartbeat_unix_ms: Some(NOW - 10),
        heartbeat_timeout_ms: 100,
        lease_expires_at_unix_ms: NOW + 1_000,
        deadline_unix_ms: NOW + 2_000,
        process,
        quota: quota(),
        effect: AttemptEffectObservation::NoneObserved,
        open_descendants: 0,
    })
}

#[test]
fn terminal_attempt_with_live_process_is_unreconciled_and_loss_visible() -> TestResult {
    let input = telemetry(
        CoordinatedAttemptState::CandidateResultSubmitted,
        ProcessObservation::Alive,
    )?;
    let projection = project_attempt_health(&input, NOW)?;

    assert_eq!(
        projection.terminal_reconciliation,
        AttemptTerminalReconciliation::Unreconciled
    );
    assert!(
        projection
            .alerts
            .contains(&AttemptAlertCode::TerminalProcessAlive)
    );
    assert_eq!(
        projection.automation,
        AttemptAutomationDisposition::ManualOnly
    );
    Ok(())
}

#[test]
fn terminal_attempt_with_unknown_process_is_unreconciled_and_loss_visible() -> TestResult {
    let input = telemetry(
        CoordinatedAttemptState::CandidateResultSubmitted,
        ProcessObservation::Unknown,
    )?;
    let projection = project_attempt_health(&input, NOW)?;

    assert_eq!(
        projection.terminal_reconciliation,
        AttemptTerminalReconciliation::Unreconciled
    );
    assert!(
        projection
            .alerts
            .contains(&AttemptAlertCode::ProcessUnknown)
    );
    Ok(())
}

#[test]
fn terminal_attempt_with_exited_process_reconciles_without_missing_process_alert() -> TestResult {
    let input = telemetry(
        CoordinatedAttemptState::CandidateResultSubmitted,
        ProcessObservation::Exited,
    )?;
    let projection = project_attempt_health(&input, NOW)?;

    assert_eq!(
        projection.terminal_reconciliation,
        AttemptTerminalReconciliation::ReconciledCandidate
    );
    assert!(
        !projection
            .alerts
            .contains(&AttemptAlertCode::ProcessMissing)
    );
    Ok(())
}

#[test]
fn nonterminal_attempt_with_exited_process_remains_missing_and_unreconciled() -> TestResult {
    let input = telemetry(CoordinatedAttemptState::Running, ProcessObservation::Exited)?;
    let projection = project_attempt_health(&input, NOW)?;

    assert_eq!(
        projection.terminal_reconciliation,
        AttemptTerminalReconciliation::Unreconciled
    );
    assert!(
        projection
            .alerts
            .contains(&AttemptAlertCode::ProcessMissing)
    );
    Ok(())
}
