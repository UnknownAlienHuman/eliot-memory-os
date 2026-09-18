#![allow(clippy::unwrap_used)]

use eliot_contracts::RequestId;
use eliot_store_api::{
    MAX_STORE_FAILURE_EVIDENCE_HANDLES, OperationId,
    StoreConflictObservation, StoreError, StoreEvidenceHandles, StoreFailure,
    StoreFailureContractError, StoreFailureDisposition, StoreFailureIdentityContext,
    StoreMutationDisposition, StoreReasonCode, StoreRecoveryAction, StoreResponse,
    StoreRetryDirective, decode_response_frame, response_frame,
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
fn typed_failure_frame_remains_decodable() {
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
fn semantic_digest_is_stable_under_human_rewording() {
    let base = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    let undetailed = base.semantic_digest().unwrap();
    let mut first = base.clone();
    first.human_detail = Some("provider wording one".to_owned());
    let mut second = base;
    second.human_detail = Some("provider wording two".to_owned());
    assert_eq!(first, second);
    assert_eq!(first.semantic_digest().unwrap(), undetailed);
    assert_eq!(second.semantic_digest().unwrap(), undetailed);
}

#[test]
fn semantic_digest_detects_machine_tamper_and_bad_revision_fails_closed() {
    let failure = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    let digest = failure.semantic_digest().unwrap();
    let mut tampered = failure.clone();
    tampered.reason_code = StoreReasonCode::new("FUTURE_STORE_REASON").unwrap();
    assert_ne!(tampered.semantic_digest().unwrap(), digest);
    tampered.validate().unwrap();

    let mut bad_revision = failure.clone();
    bad_revision.contract_revision = "eliot.store.failure.v1".to_owned();
    assert!(bad_revision.validate().is_err());

    // Denied is an explicit arm of the v2 contour: a DENIED disposition
    // decodes to the arm instead of failing closed.
    let mut denied_value = serde_json::to_value(&failure).unwrap();
    denied_value["disposition"] = serde_json::json!("DENIED");
    let denied: StoreFailure = serde_json::from_value(denied_value).unwrap();
    assert_eq!(denied.disposition, StoreFailureDisposition::Denied);
}

#[test]
fn conflict_disposition_requires_typed_details() {
    let detailed = StoreFailure::from_store_error(StoreError::RevisionConflict, context()).unwrap();
    assert!(detailed.conflict.is_some());
    detailed.validate().unwrap();

    let mut stripped = detailed.clone();
    stripped.conflict = None;
    assert!(stripped.validate().is_err());

    let mut empty = detailed;
    empty.conflict = Some(StoreConflictObservation::default());
    assert!(empty.validate().is_err());
}

#[test]
fn fence_conflict_evidence_requires_distinct_fences() {
    let mut failure = StoreFailure::from_store_error(StoreError::FenceMismatch, context()).unwrap();
    failure.conflict = Some(StoreConflictObservation {
        expected_state_fence_ref: Some("fence-expected".to_owned()),
        observed_state_fence_ref: Some("fence-expected".to_owned()),
        ..Default::default()
    });
    assert!(failure.validate().is_err());

    failure.conflict = Some(StoreConflictObservation {
        expected_state_fence_ref: Some("fence-expected".to_owned()),
        observed_state_fence_ref: Some("fence-observed".to_owned()),
        ..Default::default()
    });
    failure.validate().unwrap();
}

#[test]
fn evidence_handles_are_bounded_and_unique() {
    let valid =
        StoreEvidenceHandles::new(vec!["evidence-a".to_owned(), "evidence-b".to_owned()]).unwrap();
    assert_eq!(valid.len(), 2);
    assert!(!valid.is_empty());
    let round_tripped: StoreEvidenceHandles =
        serde_json::from_value(serde_json::to_value(&valid).unwrap()).unwrap();
    assert_eq!(round_tripped, valid);

    assert!(StoreEvidenceHandles::new(vec!["dup".to_owned(), "dup".to_owned()]).is_err());
    assert!(StoreEvidenceHandles::new(vec![String::new()]).is_err());
    let oversized = (0..=MAX_STORE_FAILURE_EVIDENCE_HANDLES)
        .map(|index| format!("evidence-{index}"))
        .collect::<Vec<_>>();
    assert!(StoreEvidenceHandles::new(oversized).is_err());
}

#[test]
fn same_identity_retry_requires_request_or_idempotency_evidence() {
    let mut failure = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    failure.request_id = None;
    failure.idempotency_key_ref_or_digest = None;
    assert!(failure.validate().is_err());

    failure.request_id = context().request_id;
    failure.validate().unwrap();
}

#[test]
fn retry_after_requires_a_nonzero_future_delay() {
    let mut failure = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    failure.retry_after_dependency_revision = Some("dependency-revision-1".to_owned());
    failure.retry_after_ms = Some(0);
    assert!(failure.validate().is_err());

    failure.retry_after_ms = Some(250);
    failure.validate().unwrap();
}

#[test]
fn disposition_fixtures_cover_backpressure_migration_and_unknown_outcome() {
    let mut backpressure =
        StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    backpressure.disposition = StoreFailureDisposition::Backpressured;
    backpressure.reason_code = StoreReasonCode::new("STORE_BACKPRESSURED").unwrap();
    backpressure.recovery_action = StoreRecoveryAction::WaitForCapacity;
    backpressure.retry_after_ms = Some(250);
    backpressure.retry_after_dependency_revision = Some("dependency-revision-1".to_owned());
    backpressure.validate().unwrap();

    let mut migration = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    migration.disposition = StoreFailureDisposition::MigrationRequired;
    migration.reason_code = StoreReasonCode::new("SCHEMA_MIGRATION_REQUIRED").unwrap();
    migration.retry_directive = StoreRetryDirective::MigrateThenRetryNewIdentity;
    migration.recovery_action = StoreRecoveryAction::RunSchemaMigration;
    migration.retry_after_ms = None;
    migration.validate().unwrap();

    let unknown =
        StoreFailure::from_store_error(StoreError::MissingReceiptEnvelope, context()).unwrap();
    unknown.validate().unwrap();
    assert_ne!(
        backpressure.semantic_digest().unwrap(),
        migration.semantic_digest().unwrap()
    );
}

#[test]
fn malformed_and_oversized_wire_fields_fail_closed() {
    let failure = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    let mut unknown_field = serde_json::to_value(&failure).unwrap();
    unknown_field["future_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<StoreFailure>(unknown_field).is_err());

    let mut oversized = failure;
    oversized.evidence_ref = Some("x".repeat(eliot_store_api::MAX_STORE_FAILURE_REFERENCE_LEN + 1));
    assert!(oversized.validate().is_err());
}

#[test]
fn denied_and_not_applicable_with_evidence_handles() {
    let mut failure = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    failure.disposition = StoreFailureDisposition::Denied;
    failure.mutation_disposition = StoreMutationDisposition::NotApplicable;
    failure.retry_directive = StoreRetryDirective::DoNotRetry;
    failure.evidence_handles = StoreEvidenceHandles::new(vec!["a".to_owned()]).unwrap();
    failure.validate().unwrap();
    let round_tripped: StoreFailure =
        serde_json::from_value(serde_json::to_value(&failure).unwrap()).unwrap();
    assert_eq!(round_tripped, failure);
    let digest = failure.semantic_digest().unwrap();
    let mut tampered = failure.clone();
    tampered.evidence_handles = StoreEvidenceHandles::new(vec!["b".to_owned()]).unwrap();
    assert_ne!(tampered.semantic_digest().unwrap(), digest);
    assert!(StoreEvidenceHandles::new(vec!["dup".to_owned(), "dup".to_owned()]).is_err());
    let mut missing = StoreFailure::from_store_error(StoreError::Unavailable, context()).unwrap();
    missing.retry_after_ms = Some(250);
    assert!(missing.validate().is_err());
}
