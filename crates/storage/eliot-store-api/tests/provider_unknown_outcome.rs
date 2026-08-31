use eliot_contracts::{AuthorityEpoch, OperationId, RequestId, ResourceGeneration, StateFence};
use eliot_store_api::{
    StoreFailure, StoreFailureContractError, StoreFailureDisposition, StoreFailureIdentityContext,
    StoreMutationDisposition, StoreRecoveryAction, StoreRetryDirective,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn context() -> TestResult<StoreFailureIdentityContext> {
    Ok(StoreFailureIdentityContext {
        request_id: Some(RequestId::new("request-provider-unknown")?),
        operation_id: Some(OperationId::new("operation-provider-unknown")?),
        idempotency_key_ref_or_digest: Some("retry-provider-unknown".to_owned()),
        state_fence_ref_or_exact_safe_projection: Some(StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::genesis(),
        )),
        evidence_ref: Some("evidence:provider-unknown".to_owned()),
        transport_unavailable: false,
    })
}

#[test]
fn provider_unknown_outcome_is_exact_and_reconciliation_only() -> TestResult {
    let failure = StoreFailure::provider_unknown_outcome(context()?)?;
    failure.validate()?;

    assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);
    assert_eq!(failure.reason_code.as_str(), "PROVIDER_OUTCOME_UNKNOWN");
    assert_eq!(
        failure.operation_id.as_ref().map(OperationId::as_str),
        Some("operation-provider-unknown")
    );
    assert_eq!(failure.mutation_disposition, StoreMutationDisposition::Unknown);
    assert_eq!(
        failure.retry_directive,
        StoreRetryDirective::ReconcileExactOperation
    );
    assert_eq!(
        failure.recovery_action,
        StoreRecoveryAction::ReconcileUnknownOutcome
    );
    assert!(failure.human_detail.is_none());
    Ok(())
}

#[test]
fn provider_unknown_outcome_requires_operation_identity() -> TestResult {
    let mut context = context()?;
    context.operation_id = None;
    assert_eq!(
        StoreFailure::provider_unknown_outcome(context),
        Err(StoreFailureContractError::MissingOperationIdentity)
    );
    Ok(())
}

#[test]
fn human_wording_does_not_change_provider_unknown_control_equality() -> TestResult {
    let mut first = StoreFailure::provider_unknown_outcome(context()?)?;
    first.human_detail = Some("provider response ended before disposition".to_owned());
    first.validate()?;

    let mut second = first.clone();
    second.human_detail = Some("different bounded diagnostic wording".to_owned());
    second.validate()?;

    assert_eq!(first, second);
    Ok(())
}
