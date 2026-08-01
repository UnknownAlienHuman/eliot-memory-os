use anyhow::{Context, Result};
use eliot_engine::{ProviderInvocationJournal, ProviderProcessOutcome};
use eliot_types::{ProviderInvocationAttempt, ProviderInvocationState};

/// Owns the app-layer decision for a supervisor failure after dispatch. The
/// caller may report the error, but it must not choose a retryable state.
pub(super) fn record_post_dispatch_supervisor_failure(
    journal: &ProviderInvocationJournal,
    attempt: &mut ProviderInvocationAttempt,
    error_text: &str,
) -> Result<(), eliot_engine::EngineError> {
    journal.record_post_dispatch_failure(attempt, vec![format!("supervisor_error:{error_text}")])
}

/// Persists observed process terminal facts before output capture, parsing, or
/// schema admission can fail.
pub(super) fn record_terminal_process(
    journal: &ProviderInvocationJournal,
    attempt: &mut ProviderInvocationAttempt,
    process: &ProviderProcessOutcome,
) -> Result<(), eliot_engine::EngineError> {
    journal.record_process_terminal(attempt, process)
}

/// Finalizes a provider-free historical reconciliation without manufacturing
/// process or output facts. Replays are idempotent and can only converge on the
/// fail-closed unknown state.
pub(super) fn terminalize_historical_unknown(
    journal: &ProviderInvocationJournal,
    attempt: &mut ProviderInvocationAttempt,
    resolution_ref: &str,
) -> Result<()> {
    let current = attempt
        .state_transitions
        .last()
        .map(|transition| transition.to)
        .context("historical attempt has no state")?;
    if current == ProviderInvocationState::Running {
        journal.transition(
            attempt,
            ProviderInvocationState::TimeoutPendingReconciliation,
            vec![resolution_ref.to_owned()],
        )?;
    }
    let current = attempt
        .state_transitions
        .last()
        .map(|transition| transition.to)
        .context("historical attempt has no state")?;
    if matches!(
        current,
        ProviderInvocationState::TimeoutPendingReconciliation
            | ProviderInvocationState::ProcessTerminal
    ) {
        journal.transition(
            attempt,
            ProviderInvocationState::NonReconcilableUnknown,
            vec![
                resolution_ref.to_owned(),
                "provider_redispatch_forbidden:true".to_owned(),
            ],
        )?;
    }
    anyhow::ensure!(
        attempt
            .state_transitions
            .last()
            .map(|transition| transition.to)
            == Some(ProviderInvocationState::NonReconcilableUnknown),
        "historical attempt did not reach NonReconcilableUnknown"
    );
    Ok(())
}
