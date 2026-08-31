#![allow(clippy::expect_used)]

use eliot_contracts::{
    AuthorityEpoch, ClockReading, OperationId, ProductId, RequestId, ResourceGeneration, SourceId,
    StateFence,
};
use eliot_store_api::{
    CommitId, CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, OperationIdentity,
    OperationManifestDigest, OrderingScopeId, OWNER_SNAPSHOT_SCHEMA, PreparedTransition,
    RecoveryRecord, RequestMeta, Resubmission, ScopeId, SecurityContext, StoreError, StoreFailure,
    StoreFailureDisposition, StoreFailureIdentityContext, StoreGenesisRequest,
    StoreMutationDisposition, StoreRecoveryAction, StoreRetryDirective, TransitionClass,
    WriteReceipt, WriteReceiptStatus, genesis_transition, issue_store_receipt_envelope, sha256_hex,
};

use super::{
    PROVIDER_OPERATION_ID_MISMATCH, RECEIPT_ENVELOPE_MISSING,
    RECEIPT_OPERATION_ID_MISMATCH, map_apply_receipt, map_genesis_receipt,
    map_provider_unknown_outcome, map_receipt_lookup, request_failure_context,
    typed_failure_response,
};
use crate::{Request, Response};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn request_meta(request_id: &str) -> TestResult<RequestMeta> {
    Ok(RequestMeta {
        request_id: RequestId::new(request_id)?,
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-store-typed-failure")?,
        source_id: SourceId::new("source-store-typed-failure")?,
        state_fence: fence(),
        clock: ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_001),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
    })
}

fn transition(operation_id: &str, idempotency_key: &str) -> TestResult<PreparedTransition> {
    Ok(PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(operation_id)?,
            idempotency_key: idempotency_key.to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("scope-store-typed-failure")?,
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("scope-store-typed-failure")?],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: OperationManifestDigest::new("manifest-store-typed-failure")?,
        named_operations: Vec::new(),
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    })
}

fn apply_request(context: &RequestMeta, transition: &PreparedTransition) -> Request {
    Request::Apply {
        context: context.clone(),
        transition: transition.clone(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    }
}

fn apply_receipt(transition: &PreparedTransition) -> TestResult<WriteReceipt> {
    Ok(WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-store-typed-failure")?),
        state_fence: transition.state_fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["capture-store-typed-failure".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    })
}

fn typed_failure(response: Response) -> StoreFailure {
    let Response::Failure { failure } = response else {
        panic!("expected typed Store failure");
    };
    failure
}

fn genesis_request() -> TestResult<StoreGenesisRequest> {
    let payload = br#"{"current_plan":null}"#.to_vec();
    Ok(StoreGenesisRequest {
        contract_version: CONTRACT_VERSION,
        operation_id: OperationId::new("operation-genesis-typed-failure")?,
        idempotency_key: "retry-genesis-typed-failure".to_owned(),
        canonical_request_hash: String::new(),
        state_fence: fence(),
        owner_records: vec![RecoveryRecord {
            namespace: "owner".to_owned(),
            key: "current".to_owned(),
            state_fence: fence(),
            revision: 1,
            schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
            value_digest: sha256_hex(&payload),
            payload,
        }],
    }
    .with_computed_digest()?)
}

fn genesis_receipt(context: &RequestMeta, request: &StoreGenesisRequest) -> TestResult<WriteReceipt> {
    let transition = genesis_transition(context, request)?;
    Ok(WriteReceipt {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        canonical_request_hash: request.canonical_request_hash.clone(),
        transition_class: TransitionClass::RecoverySchema,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-genesis-typed-failure")?),
        state_fence: request.state_fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["initialize-genesis".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: transition.operation_manifest_digest,
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    })
}

#[test]
fn store_error_families_keep_distinct_machine_semantics() -> TestResult {
    let request_id = RequestId::new("request-error-families")?;
    for (error, reason, disposition) in [
        (
            StoreError::RevisionConflict,
            "REVISION_CONFLICT",
            StoreFailureDisposition::Conflict,
        ),
        (
            StoreError::FenceMismatch,
            "STATE_FENCE_MISMATCH",
            StoreFailureDisposition::Conflict,
        ),
        (
            StoreError::Unavailable,
            "STORE_UNAVAILABLE",
            StoreFailureDisposition::Unavailable,
        ),
        (
            StoreError::InvalidField {
                field: "fixture",
                reason: "fixture rejection",
            },
            "INVALID_FIELD",
            StoreFailureDisposition::DeterministicRejection,
        ),
    ] {
        let response = typed_failure_response(
            error,
            StoreFailureIdentityContext {
                request_id: Some(request_id.clone()),
                ..StoreFailureIdentityContext::default()
            },
        )?;
        let failure = typed_failure(response);
        assert_eq!(failure.request_id.as_ref(), Some(&request_id));
        assert_eq!(failure.reason_code.as_str(), reason);
        assert_eq!(failure.disposition, disposition);
        failure.validate()?;
    }
    Ok(())
}

#[test]
fn apply_failure_context_preserves_exact_request_operation_retry_and_fence() -> TestResult {
    let context = request_meta("request-apply-context")?;
    let transition = transition("operation-apply-context", "retry-apply-context")?;
    let request = apply_request(&context, &transition);
    let failure_context = request_failure_context(context.request_id.clone(), &request);

    assert_eq!(failure_context.request_id, Some(context.request_id));
    assert_eq!(
        failure_context.operation_id.as_ref(),
        Some(&transition.identity.operation_id)
    );
    assert_eq!(
        failure_context.idempotency_key_ref_or_digest.as_deref(),
        Some("retry-apply-context")
    );
    assert_eq!(
        failure_context
            .state_fence_ref_or_exact_safe_projection
            .as_ref(),
        Some(&transition.state_fence)
    );
    Ok(())
}

#[test]
fn provider_operation_b_cannot_replace_admitted_operation_a() -> TestResult {
    let context = request_meta("request-provider-mismatch")?;
    let transition = transition("operation-admitted-a", "retry-admitted-a")?;
    let request = apply_request(&context, &transition);
    let failure_context = request_failure_context(context.request_id, &request);
    let observed = OperationId::new("operation-provider-b")?;

    let failure = typed_failure(map_provider_unknown_outcome(failure_context, &observed)?);
    assert_eq!(
        failure.operation_id.as_ref(),
        Some(&transition.identity.operation_id)
    );
    assert_eq!(
        failure.evidence_ref.as_deref(),
        Some(PROVIDER_OPERATION_ID_MISMATCH)
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
    Ok(())
}

#[test]
fn missing_apply_receipt_envelope_is_typed_unknown_for_admitted_operation() -> TestResult {
    let context = request_meta("request-apply-missing-envelope")?;
    let transition = transition(
        "operation-apply-missing-envelope",
        "retry-apply-missing-envelope",
    )?;
    let request = apply_request(&context, &transition);
    let failure_context = request_failure_context(context.request_id.clone(), &request);
    let receipt = apply_receipt(&transition)?;
    receipt.validate()?;

    let failure = typed_failure(map_apply_receipt(
        &context,
        &transition,
        failure_context,
        receipt,
    )?);
    assert_eq!(
        failure.operation_id.as_ref(),
        Some(&transition.identity.operation_id)
    );
    assert_eq!(
        failure.evidence_ref.as_deref(),
        Some(RECEIPT_ENVELOPE_MISSING)
    );
    assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);
    Ok(())
}

#[test]
fn exact_apply_receipt_envelope_remains_success() -> TestResult {
    let context = request_meta("request-apply-valid-envelope")?;
    let transition = transition(
        "operation-apply-valid-envelope",
        "retry-apply-valid-envelope",
    )?;
    let request = apply_request(&context, &transition);
    let failure_context = request_failure_context(context.request_id.clone(), &request);
    let mut receipt = apply_receipt(&transition)?;
    receipt.envelope = Some(issue_store_receipt_envelope(
        &context,
        &transition,
        &receipt,
        1,
    )?);

    let response = map_apply_receipt(
        &context,
        &transition,
        failure_context,
        receipt.clone(),
    )?;
    assert_eq!(response, Response::Transaction { receipt });
    Ok(())
}

#[test]
fn receipt_lookup_mismatch_preserves_queried_operation_identity() -> TestResult {
    let queried = OperationId::new("operation-receipt-query-a")?;
    let request_id = RequestId::new("request-receipt-query")?;
    let request = Request::Receipt {
        operation_id: queried.clone(),
    };
    let failure_context = request_failure_context(request_id, &request);
    let transition = transition("operation-receipt-returned-b", "retry-returned-b")?;
    let receipt = apply_receipt(&transition)?;

    let failure = typed_failure(map_receipt_lookup(
        &queried,
        failure_context,
        Some(receipt),
    )?);
    assert_eq!(failure.operation_id.as_ref(), Some(&queried));
    assert_eq!(
        failure.evidence_ref.as_deref(),
        Some(RECEIPT_OPERATION_ID_MISMATCH)
    );
    Ok(())
}

#[test]
fn missing_genesis_receipt_envelope_is_typed_unknown_for_requested_operation() -> TestResult {
    let context = request_meta("request-genesis-missing-envelope")?;
    let request = genesis_request()?;
    let dispatch_request = Request::InitializeGenesis {
        context: context.clone(),
        request: request.clone(),
    };
    let failure_context = request_failure_context(context.request_id.clone(), &dispatch_request);
    let receipt = genesis_receipt(&context, &request)?;
    receipt.validate()?;

    let failure = typed_failure(map_genesis_receipt(
        &context,
        &request,
        failure_context,
        receipt,
    )?);
    assert_eq!(failure.operation_id.as_ref(), Some(&request.operation_id));
    assert_eq!(
        failure.evidence_ref.as_deref(),
        Some(RECEIPT_ENVELOPE_MISSING)
    );
    assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);
    Ok(())
}

#[test]
fn current_producer_source_has_no_live_legacy_failure_construction() {
    let dispatch_source = include_str!("../request_dispatch.rs");
    let dispatch_live = dispatch_source
        .split_once("#[cfg(test)]")
        .map_or(dispatch_source, |(live, _)| live);
    assert!(!dispatch_live.contains("Response::Error"));
    assert!(!dispatch_live.contains("Response::Unknown"));

    let main_source = include_str!("../main.rs");
    assert!(!main_source.contains("Response::Error"));
    assert!(!main_source.contains("Response::Unknown"));
}
