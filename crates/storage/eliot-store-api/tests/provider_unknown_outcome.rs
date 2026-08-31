#![allow(clippy::unwrap_used)]

use eliot_contracts::{OperationId, RequestId};
use eliot_store_api::{
    StoreError, StoreFailure, StoreFailureContractError, StoreFailureDisposition,
    StoreFailureIdentityContext, StoreMutationDisposition, StoreRecoveryAction,
    StoreRetryDirective,
};

fn context() -> StoreFailureIdentityContext {
    StoreFailureIdentityContext {
        request_id: Some(RequestId::new("request-a").unwrap()),
        operation_id: Some(OperationId::new("operation-a").unwrap()),
        idempotency_key_ref_or_digest: Some("request-digest-a".to_owned()),
        state_fence_ref_or_exact_safe_projection: None,
        evidence_ref: Some("evidence-a".to_owned()),
        transport_unavailable: false,
    }
}

#[test]
fn provider_unknown_outcome_preserves_admitted_identity_and_reconciliation() {
    let context = context();
    let failure = StoreFailure::from_provider_unknown_outcome(&context).unwrap();

    assert_eq!(
        failure.operation_id,
        Some(OperationId::new("operation-a").unwrap())
    );
    assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);
    assert_eq!(failure.reason_code.as_str(), "PROVIDER_OUTCOME_UNKNOWN");
    assert_eq!(
        failure.mutation_disposition,
        StoreMutationDisposition::Unknown
    );
    assert_eq!(
        failure.retry_directive,
        StoreRetryDirective::ReconcileExactOperation
    );
    assert_eq!(
        failure.recovery_action,
        StoreRecoveryAction::ReconcileUnknownOutcome
    );
    assert!(failure.human_detail.is_none());
    failure.validate().unwrap();
}

#[test]
fn provider_unknown_outcome_requires_an_admitted_operation_identity() {
    let mut context = context();
    context.operation_id = None;

    assert_eq!(
        StoreFailure::from_provider_unknown_outcome(&context),
        Err(StoreFailureContractError::MissingOperationIdentity)
    );
}

#[test]
fn provider_unknown_operation_identity_cannot_replace_the_admitted_operation() {
    let context = context();
    let failure = StoreFailure::from_provider_unknown_outcome(&context).unwrap();
    assert_ne!(
        failure.operation_id,
        Some(OperationId::new("operation-b").unwrap())
    );
}

#[test]
fn provider_prose_does_not_change_unknown_outcome_control_equality() {
    let context = context();
    let mut with_detail = StoreFailure::from_provider_unknown_outcome(&context).unwrap();
    let without_detail = with_detail.clone();
    with_detail.human_detail = Some("provider wording changed".to_owned());

    assert_eq!(with_detail, without_detail);
    with_detail.validate().unwrap();
}

#[test]
fn receipt_unknown_mapping_keeps_provider_unknown_distinct_from_unavailable() {
    let receipt_unknown =
        StoreFailure::from_store_error(StoreError::MissingReceiptEnvelope, context()).unwrap();
    let unavailable = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();

    assert_eq!(
        receipt_unknown.disposition,
        StoreFailureDisposition::UnknownOutcome
    );
    assert_eq!(
        receipt_unknown.retry_directive,
        StoreRetryDirective::ReconcileExactOperation
    );
    assert_eq!(
        unavailable.disposition,
        StoreFailureDisposition::Unavailable
    );
    assert_ne!(receipt_unknown, unavailable);
}
