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

#[test]
fn future_heartbeat_cannot_become_live_through_saturating_age()
-> Result<(), Box<dyn std::error::Error>> {
    let input = AttemptTelemetryInput {
        attempt_id: AttemptId::new("attempt-future-heartbeat")?,
        state: CoordinatedAttemptState::Running,
        observed_at_unix_ms: NOW,
        started_at_unix_ms: NOW - 1_000,
        last_heartbeat_unix_ms: Some(NOW + 1_000),
        heartbeat_timeout_ms: 100,
        lease_expires_at_unix_ms: NOW + 2_000,
        deadline_unix_ms: NOW + 3_000,
        process: ProcessObservation::Alive,
        quota: quota(),
        effect: AttemptEffectObservation::NoneObserved,
        open_descendants: 0,
    };

    assert_eq!(
        project_attempt_health(&input, NOW),
        Err(ModelControlError::InvalidField(
            "attempt_telemetry.last_heartbeat_unix_ms"
        ))
    );
    Ok(())
}
