#![allow(clippy::unwrap_used)]

use eliot_contracts::RequestId;
use eliot_store_api::{
    LegacyStoreFailureV1, OperationId, StoreError, StoreFailure, StoreFailureContractError,
    StoreFailureDisposition, StoreFailureIdentityContext, StoreMutationDisposition, StoreResponse,
    StoreRetryDirective, decode_legacy_store_failure_v1, decode_response_frame, response_frame,
};

fn context() -> StoreFailureIdentityContext {
    StoreFailureIdentityContext {
        request_id: Some(RequestId::new("request-1").unwrap()),
        operation_id: Some(OperationId::new("operation-1").unwrap()),
        idempotency_key_ref_or_digest: Some("idempotency-1".to_owned()),
        state_fence_ref_or_exact_safe_projection: None,
        evidence_ref: Some("evidence-1".to_owned()),
        transport_unavailable: false,
    }
}

#[test]
fn v2_failure_round_trips_with_future_reason_code() {
    let mut failure =
        StoreFailure::from_store_error(StoreError::RevisionConflict, context()).unwrap();
    failure.reason_code = eliot_store_api::StoreReasonCode::new("FUTURE_STORE_REASON").unwrap();
    failure.human_detail = Some("provider wording may change".to_owned());
    let response = StoreResponse::Failure { failure };
    let encoded = serde_json::to_value(&response).unwrap();
    let decoded: StoreResponse = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, response);
    decoded.validate().unwrap();
}

#[test]
fn invalid_unknown_and_partial_combinations_are_rejected() {
    let mut unknown =
        StoreFailure::from_store_error(StoreError::MissingReceiptEnvelope, context()).unwrap();
    unknown.retry_directive = StoreRetryDirective::RetrySameIdentityAfterBackoff;
    assert!(unknown.validate().is_err());

    let mut partial = StoreFailure::from_store_error(
        StoreError::InvalidField {
            field: "field",
            reason: "invalid",
        },
        context(),
    )
    .unwrap();
    partial.mutation_disposition = StoreMutationDisposition::Partial;
    assert!(partial.validate().is_err());
}

#[test]
fn human_detail_is_serialized_but_not_semantic_equality() {
    let mut first = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    let mut second = first.clone();
    first.human_detail = Some("provider wording one".to_owned());
    second.human_detail = Some("provider wording two".to_owned());
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_value(&first).unwrap()["human_detail"],
        "provider wording one"
    );
    first.validate().unwrap();
    second.validate().unwrap();
}

#[test]
fn store_error_mapping_keeps_machine_categories_distinct() {
    let revision = StoreFailure::from_store_error(StoreError::RevisionConflict, context()).unwrap();
    let ordering = StoreFailure::from_store_error(StoreError::OrderingConflict, context()).unwrap();
    let fence = StoreFailure::from_store_error(StoreError::FenceMismatch, context()).unwrap();
    let unavailable = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    let unsupported =
        StoreFailure::from_store_error(StoreError::UnknownOperation, context()).unwrap();
    assert_eq!(revision.reason_code.as_str(), "REVISION_CONFLICT");
    assert_eq!(ordering.reason_code.as_str(), "ORDERING_CONFLICT");
    assert_eq!(fence.reason_code.as_str(), "STATE_FENCE_MISMATCH");
    assert_eq!(
        unavailable.disposition,
        StoreFailureDisposition::Unavailable
    );
    assert_eq!(
        unsupported.disposition,
        StoreFailureDisposition::Unsupported
    );
    assert_eq!(unsupported.retry_directive, StoreRetryDirective::DoNotRetry);
}

#[test]
fn unknown_outcome_requires_exact_identity_and_reconciliation() {
    let failure =
        StoreFailure::from_store_error(StoreError::MissingReceiptEnvelope, context()).unwrap();
    assert_eq!(failure.operation_id, context().operation_id);
    assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);
    assert_eq!(
        failure.mutation_disposition,
        StoreMutationDisposition::Unknown
    );
    assert_eq!(
        failure.retry_directive,
        StoreRetryDirective::ReconcileExactOperation
    );

    let mut no_operation = context();
    no_operation.operation_id = None;
    assert_eq!(
        StoreFailure::from_store_error(StoreError::MissingReceiptEnvelope, no_operation),
        Err(StoreFailureContractError::MissingOperationIdentity)
    );
}

#[test]
fn legacy_unknown_and_error_remain_compatible_without_text_parsing() {
    let unknown_value = serde_json::json!({
        "status": "unknown",
        "operation_id": "legacy-operation",
        "reason": "provider response was interrupted"
    });
    let failure = decode_legacy_store_failure_v1(&unknown_value, &context()).unwrap();
    assert_eq!(failure.reason_code.as_str(), "PROVIDER_OUTCOME_UNKNOWN");
    assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);

    let error_value = serde_json::json!({
        "status": "error",
        "error": "provider is unavailable but this is only human detail"
    });
    let error = decode_legacy_store_failure_v1(&error_value, &context()).unwrap();
    assert_eq!(error.disposition, StoreFailureDisposition::InternalDefect);
    let mut unavailable_context = context();
    unavailable_context.transport_unavailable = true;
    let unavailable = decode_legacy_store_failure_v1(&error_value, &unavailable_context).unwrap();
    assert_eq!(
        unavailable.disposition,
        StoreFailureDisposition::Unavailable
    );
}

#[test]
fn legacy_store_response_variants_and_v2_frame_remain_decodable() {
    let error: StoreResponse = serde_json::from_value(serde_json::json!({
        "status": "error", "error": "legacy failure"
    }))
    .unwrap();
    let unknown: StoreResponse = serde_json::from_value(serde_json::json!({
        "status": "unknown", "operation_id": "operation-1", "reason": "legacy unknown"
    }))
    .unwrap();
    assert!(matches!(error, StoreResponse::Error { .. }));
    assert!(matches!(unknown, StoreResponse::Unknown { .. }));
    error.validate().unwrap();
    unknown.validate().unwrap();

    let response = StoreResponse::Failure {
        failure: StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap(),
    };
    let request_id = RequestId::new("request-1").unwrap();
    let frame = response_frame(
        "connection-1",
        eliot_protocol::ProtocolVersion::CURRENT,
        Some(request_id),
        response,
    )
    .unwrap();
    let (_, decoded) = decode_response_frame(
        &frame,
        "connection-1",
        eliot_protocol::ProtocolVersion::CURRENT,
    )
    .unwrap();
    assert!(matches!(decoded, StoreResponse::Failure { .. }));
}

#[test]
fn legacy_enum_rejects_unknown_fields() {
    let value = serde_json::json!({
        "status": "error",
        "error": "legacy failure",
        "future": true
    });
    assert!(serde_json::from_value::<LegacyStoreFailureV1>(value).is_err());
}

#[test]
fn legacy_wire_detail_is_bounded_before_ebp_crossing() {
    let oversized = "x".repeat(eliot_store_api::MAX_STORE_FAILURE_DETAIL_LEN + 1);
    let error: StoreResponse = serde_json::from_value(serde_json::json!({
        "status": "error",
        "error": oversized
    }))
    .unwrap();
    assert!(error.validate().is_err());
}
