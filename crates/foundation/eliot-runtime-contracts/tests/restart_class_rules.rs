use std::error::Error;

use eliot_runtime_contracts::{
    AutomaticRestartDecision, RestartClass, RestartFailureEvidence, RestartGroupStrategy,
    RestartIdentityEvidence, RestartIntensityPolicy, RestartOwnerLifecycle, RestartPolicyV1,
    decide_automatic_restart,
};

fn policy_for(restart_class: RestartClass) -> RestartPolicyV1 {
    RestartPolicyV1 {
        policy_version: 1,
        subject_id: "child-a".to_owned(),
        restart_class,
        group_id: "daemon-group".to_owned(),
        group_strategy: RestartGroupStrategy::OneForOne,
        one_for_all_rationale: None,
        dependencies: Vec::new(),
        intensity: RestartIntensityPolicy {
            max_attempts_in_window: 3,
            window_millis: 600_000,
            backoff_initial_millis: 1_000,
            backoff_max_millis: 10_000,
            jitter_max_millis: 500,
            cooldown_millis: 5_000,
            reset_after_healthy_millis: 60_000,
            quarantine_after_attempts: 3,
            escalation_target: "manual-recovery".to_owned(),
        },
        source_manifest_revision: 1,
        source_profile_revision: 1,
    }
}

#[test]
fn exited_without_readiness_obeys_each_restart_class() -> Result<(), Box<dyn Error>> {
    let lifecycle = RestartOwnerLifecycle::Running;
    let identity = RestartIdentityEvidence::Exact;
    let failure = RestartFailureEvidence::ExitedWithoutReadiness;

    assert_eq!(
        decide_automatic_restart(
            &policy_for(RestartClass::Permanent),
            lifecycle,
            identity,
            failure,
        )?,
        AutomaticRestartDecision::Eligible
    );
    assert_eq!(
        decide_automatic_restart(
            &policy_for(RestartClass::Transient),
            lifecycle,
            identity,
            failure,
        )?,
        AutomaticRestartDecision::Eligible
    );
    assert_eq!(
        decide_automatic_restart(
            &policy_for(RestartClass::Temporary),
            lifecycle,
            identity,
            failure,
        )?,
        AutomaticRestartDecision::TemporaryChild
    );
    assert_eq!(
        decide_automatic_restart(
            &policy_for(RestartClass::Permanent),
            lifecycle,
            RestartIdentityEvidence::MissingOrAmbiguous,
            failure,
        )?,
        AutomaticRestartDecision::BlockedByUncertainIdentity
    );
    Ok(())
}

#[test]
fn health_failure_without_an_observed_exit_does_not_authorize_permanent_restart()
-> Result<(), Box<dyn Error>> {
    let policy = policy_for(RestartClass::Permanent);

    assert_eq!(
        decide_automatic_restart(
            &policy,
            RestartOwnerLifecycle::Running,
            RestartIdentityEvidence::Exact,
            RestartFailureEvidence::FailedHealthContract,
        )?,
        AutomaticRestartDecision::NoMatchingFailureCondition
    );
    assert_eq!(
        decide_automatic_restart(
            &policy,
            RestartOwnerLifecycle::Running,
            RestartIdentityEvidence::MissingOrAmbiguous,
            RestartFailureEvidence::FailedHealthContract,
        )?,
        AutomaticRestartDecision::BlockedByUncertainIdentity
    );
    Ok(())
}

#[test]
fn owner_shutdown_cancellation_quiescing_and_retirement_suppress_restart()
-> Result<(), Box<dyn Error>> {
    let policy = policy_for(RestartClass::Permanent);
    let identity = RestartIdentityEvidence::Exact;
    let failure = RestartFailureEvidence::ExitedWithoutReadiness;

    assert_eq!(
        decide_automatic_restart(
            &policy,
            RestartOwnerLifecycle::PlannedShutdown,
            identity,
            failure,
        )?,
        AutomaticRestartDecision::SuppressedByOwnerLifecycle
    );
    assert_eq!(
        decide_automatic_restart(
            &policy,
            RestartOwnerLifecycle::Cancellation,
            identity,
            failure,
        )?,
        AutomaticRestartDecision::SuppressedByOwnerLifecycle
    );
    assert_eq!(
        decide_automatic_restart(&policy, RestartOwnerLifecycle::Quiescing, identity, failure,)?,
        AutomaticRestartDecision::SuppressedByOwnerLifecycle
    );
    assert_eq!(
        decide_automatic_restart(&policy, RestartOwnerLifecycle::Retiring, identity, failure,)?,
        AutomaticRestartDecision::SuppressedByOwnerLifecycle
    );
    Ok(())
}

#[test]
fn exited_without_readiness_has_a_distinct_stable_wire_value() -> Result<(), Box<dyn Error>> {
    let failure = RestartFailureEvidence::ExitedWithoutReadiness;
    let encoded = serde_json::to_string(&failure)?;

    assert_eq!(encoded, "\"exited_without_readiness\"");
    assert_eq!(
        serde_json::from_str::<RestartFailureEvidence>(&encoded)?,
        failure
    );
    Ok(())
}
