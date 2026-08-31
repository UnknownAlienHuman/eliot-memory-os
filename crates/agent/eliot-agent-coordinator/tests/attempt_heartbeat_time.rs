use eliot_agent_api::AttemptId;
use eliot_agent_coordinator::{
    AttemptEffectObservation, AttemptTelemetryInput, CoordinatedAttemptState, ModelControlError,
    ProcessObservation, QuotaDisposition, QuotaObservation, project_attempt_health,
};

const NOW: u64 = 10_000;

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

fn input(
    observed_at_unix_ms: u64,
    started_at_unix_ms: u64,
    last_heartbeat_unix_ms: Option<u64>,
) -> Result<AttemptTelemetryInput, Box<dyn std::error::Error>> {
    Ok(AttemptTelemetryInput {
        attempt_id: AttemptId::new("attempt-heartbeat-time")?,
        state: CoordinatedAttemptState::Running,
        observed_at_unix_ms,
        started_at_unix_ms,
        last_heartbeat_unix_ms,
        heartbeat_timeout_ms: 100,
        lease_expires_at_unix_ms: NOW + 2_000,
        deadline_unix_ms: NOW + 3_000,
        process: ProcessObservation::Alive,
        quota: quota(),
        effect: AttemptEffectObservation::NoneObserved,
        open_descendants: 0,
    })
}

#[test]
fn heartbeat_before_start_preserves_existing_validation_error()
-> Result<(), Box<dyn std::error::Error>> {
    let input = input(NOW, NOW - 1_000, Some(NOW - 1_001))?;

    assert_eq!(
        project_attempt_health(&input, NOW),
        Err(ModelControlError::InvalidField("attempt_telemetry"))
    );
    Ok(())
}

#[test]
fn heartbeat_at_start_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let input = input(NOW, NOW - 1_000, Some(NOW - 1_000))?;

    assert_eq!(
        project_attempt_health(&input, NOW)?.status,
        eliot_agent_coordinator::AttemptLivenessStatus::HeartbeatStale
    );
    Ok(())
}

#[test]
fn heartbeat_at_observation_is_live() -> Result<(), Box<dyn std::error::Error>> {
    let input = input(NOW, NOW - 1_000, Some(NOW))?;

    assert_eq!(
        project_attempt_health(&input, NOW)?.status,
        eliot_agent_coordinator::AttemptLivenessStatus::Live
    );
    Ok(())
}

#[test]
fn heartbeat_after_observation_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let input = input(NOW, NOW - 1_000, Some(NOW + 1))?;

    assert_eq!(
        project_attempt_health(&input, NOW),
        Err(ModelControlError::InvalidField(
            "attempt_telemetry.last_heartbeat_unix_ms"
        ))
    );
    Ok(())
}

#[test]
fn heartbeat_after_now_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let input = input(NOW - 100, NOW - 1_000, Some(NOW + 1))?;

    assert_eq!(
        project_attempt_health(&input, NOW),
        Err(ModelControlError::InvalidField(
            "attempt_telemetry.last_heartbeat_unix_ms"
        ))
    );
    Ok(())
}

#[test]
fn observed_after_now_preserves_projection_error() -> Result<(), Box<dyn std::error::Error>> {
    let input = input(NOW + 1, NOW, Some(NOW))?;

    assert_eq!(
        project_attempt_health(&input, NOW),
        Err(ModelControlError::InvalidField(
            "attempt_health.now_unix_ms"
        ))
    );
    Ok(())
}

#[test]
fn compound_future_heartbeat_keeps_field_specific_precedence()
-> Result<(), Box<dyn std::error::Error>> {
    let input = input(NOW + 1, NOW, Some(NOW + 2))?;

    assert_eq!(
        project_attempt_health(&input, NOW),
        Err(ModelControlError::InvalidField(
            "attempt_telemetry.last_heartbeat_unix_ms"
        ))
    );
    Ok(())
}

#[test]
fn missing_heartbeat_remains_missing_and_ineligible() -> Result<(), Box<dyn std::error::Error>> {
    let input = input(NOW, NOW - 1_000, None)?;
    let projection = project_attempt_health(&input, NOW)?;

    assert_eq!(
        projection.status,
        eliot_agent_coordinator::AttemptLivenessStatus::HeartbeatMissing
    );
    assert_eq!(
        projection.work_eligibility,
        eliot_agent_coordinator::AttemptWorkEligibility::Ineligible
    );
    Ok(())
}
