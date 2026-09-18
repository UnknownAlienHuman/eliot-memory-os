//! Closed request dispatch seam for `eliot-store-surreal`.
//!
//! Architecture: A12.3 One governed write path, A13.2 Kernel and failure domains,
//! ARCH-AUTH-01 authority/fence-bound execution, ARCH-SEC-02 session/capability boundary,
//! ARCH-RES-01 bounded closed dispatch.
//! Implementation: I5.1 provider-owned store seam, I5.9 explicit receipt reconciliation,
//! I5.11 closed Request catalogue, B.2 bounded error surface, I14.21 deterministic dispatch,
//! I2.23 capability ownership and seam cohesion.
//!
//! Store remains the durable owner. This module only dispatches already
//! session-validated closed `Request`s, preserves exact operation identity and
//! `UnknownOutcome` without fabricating success, and never interprets Governor
//! semantics, mints authority, or owns capability/session admission (root remains
//! responsible for handshake, replay, fence and capability validation).

use eliot_protocol::dreamer_job::DurableJobRequest;
use eliot_protocol::dreamer_job::DurableJobResponse;
use eliot_store_api::CanonicalStoreClient;
use eliot_store_api::MAX_STORE_FAILURE_REFERENCE_LEN;
use eliot_store_api::RequestMeta;
use eliot_store_api::StoreError;
use eliot_store_api::StoreFailure;
use eliot_store_api::StoreFailureIdentityContext;
use eliot_store_api::StoreGenesisRequest;
use eliot_store_api::StoreRecoveryRequest;
use eliot_store_api::StoreRecoverySnapshot;
use eliot_store_api::WriteReceipt;

use crate::Request;
use crate::Response;
use crate::StoreComposition;
use crate::StoreCompositionError;

fn sanitized_owned_reference(value: Option<String>) -> Option<String> {
    let text = value.filter(|text| !text.is_empty())?;
    if text.len() > MAX_STORE_FAILURE_REFERENCE_LEN || text.chars().any(char::is_control) {
        None
    } else {
        Some(text)
    }
}

fn sanitized_identity_context(context: StoreFailureIdentityContext) -> StoreFailureIdentityContext {
    let StoreFailureIdentityContext {
        request_id,
        operation_id,
        idempotency_key_ref_or_digest,
        state_fence_ref_or_exact_safe_projection,
        evidence_ref,
        ..
    } = context;
    StoreFailureIdentityContext {
        request_id,
        operation_id,
        idempotency_key_ref_or_digest: sanitized_owned_reference(idempotency_key_ref_or_digest),
        state_fence_ref_or_exact_safe_projection: state_fence_ref_or_exact_safe_projection
            .filter(|fence| fence.validate().is_ok()),
        evidence_ref: sanitized_owned_reference(evidence_ref),
        transport_unavailable: false,
    }
}

fn internal_defect_fallback(context: &StoreFailureIdentityContext) -> Response {
    // Both attempts below take the contract's base+defect path
    // (`from_store_error` with a defect-class `StoreError` runs
    // `StoreFailure::base` for the admitted identity plus safe fence
    // projection, then the defect table for
    // `InternalDefect`/`ManualRecovery`/`EscalateInternalDefect`).
    // The sanitized admitted identity always validates, so the first attempt
    // succeeds for arbitrary refs/fence; the empty default always validates,
    // so the second attempt covers a missed poisoned field. The terminal
    // divergence only triggers on an incompatible failure-contract revision
    // and never re-enters the legacy string error path.
    if let Ok(failure) = StoreFailure::from_store_error(StoreError::InvalidOutbox, context.clone())
    {
        return Response::Failure { failure };
    }
    if let Ok(failure) = StoreFailure::from_store_error(
        StoreError::InvalidOutbox,
        StoreFailureIdentityContext::default(),
    ) {
        return Response::Failure { failure };
    }
    unreachable!(
        "store failure contract rejects the empty internal defect; \
         incompatible failure-contract revision"
    );
}

fn map_store_error(error: StoreError, context: StoreFailureIdentityContext) -> Response {
    // Sanitize the admitted identity first so the contract mapping preserves
    // the original disposition (Unavailable/Conflict/etc.) whenever the
    // context carries poisoned refs/fence. Only genuinely unmappable cases
    // escalate to the bounded internal defect above, never to the legacy
    // string error variant.
    let sanitized = sanitized_identity_context(context);
    match StoreFailure::from_store_error(error, sanitized.clone()) {
        Ok(failure) => Response::Failure { failure },
        Err(_) => internal_defect_fallback(&sanitized),
    }
}

pub(crate) fn map_composition_error(
    error: StoreCompositionError,
    context: StoreFailureIdentityContext,
) -> Response {
    match error {
        StoreCompositionError::Store(error) => map_store_error(error, context),
        // The provider-reported identity is diagnostic only. The admitted
        // transition identity in `context` is the sole reconciliation key.
        // The admitted operation_id is required for UnknownOutcome; a missing
        // operation or poisoned refs/fence escalates to the bounded internal
        // defect, never to a string-shaped Unknown or legacy error.
        StoreCompositionError::UnknownOutcome { .. } => {
            let sanitized = sanitized_identity_context(context);
            match StoreFailure::from_provider_unknown_outcome(&sanitized) {
                Ok(failure) => Response::Failure { failure },
                Err(_) => internal_defect_fallback(&sanitized),
            }
        }
    }
}

fn failure_context_for_fence(
    state_fence: eliot_contracts::StateFence,
) -> StoreFailureIdentityContext {
    StoreFailureIdentityContext {
        state_fence_ref_or_exact_safe_projection: Some(state_fence),
        ..StoreFailureIdentityContext::default()
    }
}

fn failure_context_for_operation(
    context: &eliot_store_api::RequestMeta,
    operation_id: eliot_store_api::OperationId,
    idempotency_key: String,
) -> StoreFailureIdentityContext {
    StoreFailureIdentityContext {
        request_id: Some(context.request_id.clone()),
        operation_id: Some(operation_id),
        idempotency_key_ref_or_digest: Some(idempotency_key),
        state_fence_ref_or_exact_safe_projection: Some(context.state_fence.clone()),
        ..StoreFailureIdentityContext::default()
    }
}

/// Converts an `Apply` receipt into a reconciliation-safe response without
/// ever emitting the legacy `Unknown` variant.
///
/// I5.19: an invalid or envelope-less receipt after `Apply` crossed the
/// provider boundary is an unknown outcome for the exact admitted operation,
/// never a success and never a not-attempted claim. The admitted
/// `operation_id` in `context` is the sole reconciliation key; no
/// receipt-carried identity is adopted and no provider prose is attached.
fn response_for_transaction_receipt(
    receipt: WriteReceipt,
    context: StoreFailureIdentityContext,
) -> Response {
    if receipt.validate().is_ok() && receipt.require_reconciliation_envelope().is_ok() {
        return Response::Transaction { receipt };
    }
    let sanitized = sanitized_identity_context(context);
    match StoreFailure::from_store_error(StoreError::MissingReceiptEnvelope, sanitized.clone()) {
        Ok(failure) => Response::Failure { failure },
        Err(_) => internal_defect_fallback(&sanitized),
    }
}

/// Converts an exact-operation receipt lookup into a reconciliation-safe
/// response without ever emitting the legacy `Unknown` variant.
///
/// A missing receipt is a valid empty lookup, not a failure. An invalid or
/// envelope-less receipt for the admitted operation is an unknown outcome
/// bound to that exact operation identity, reconciled via receipt query.
fn response_for_receipt_lookup(
    receipt: Option<WriteReceipt>,
    context: StoreFailureIdentityContext,
) -> Response {
    match receipt {
        None => Response::Receipt { receipt: None },
        Some(receipt)
            if receipt.validate().is_ok() && receipt.require_reconciliation_envelope().is_ok() =>
        {
            Response::Receipt {
                receipt: Some(receipt),
            }
        }
        Some(_) => {
            let sanitized = sanitized_identity_context(context);
            match StoreFailure::from_store_error(
                StoreError::MissingReceiptEnvelope,
                sanitized.clone(),
            ) {
                Ok(failure) => Response::Failure { failure },
                Err(_) => internal_defect_fallback(&sanitized),
            }
        }
    }
}

pub(crate) fn map_recovery_dispatch_result(
    request: &StoreRecoveryRequest,
    result: Result<StoreRecoverySnapshot, StoreError>,
) -> Response {
    match result {
        Ok(snapshot) => Response::Recovery { snapshot },
        Err(error) => map_store_error(
            error,
            failure_context_for_fence(request.state_fence.clone()),
        ),
    }
}

pub(crate) fn map_genesis_dispatch_result(
    context: &RequestMeta,
    request: &StoreGenesisRequest,
    result: Result<WriteReceipt, StoreError>,
) -> Response {
    let failure_context = failure_context_for_operation(
        context,
        request.operation_id.clone(),
        request.idempotency_key.clone(),
    );
    match result {
        Ok(receipt) => Response::Genesis { receipt },
        Err(error) => map_store_error(error, failure_context),
    }
}

/// Converts one Dreamer ledger answer into a reconciliation-safe dispatch
/// response without ever reporting success for a mismatched answer.
///
/// S2 (issue #777): persistence stays owned by the S1 adapter behind
/// [`CanonicalStoreClient::dreamer_job`]. This seam only proves the returned
/// response answers the exact admitted request:
/// [`DurableJobResponse::validate_for`] binds fresh correlation, stable
/// mutation identity, job/scope/revision, disposition presence, and receipt
/// rules. A mismatched, foreign, or malformed answer observed after the
/// backend call is a typed unknown bound to the admitted operation — never
/// success, never a retryable unavailable, and never a semantic completion.
/// Deterministic adapter errors (conflict, unsupported, fence) pass through
/// [`map_store_error`] unchanged.
pub(crate) fn map_dreamer_dispatch_result(
    request: &DurableJobRequest,
    response: DurableJobResponse,
    context: StoreFailureIdentityContext,
) -> Response {
    if response.validate_for(request).is_ok() {
        return Response::DreamerJob { response };
    }
    map_store_error(StoreError::MissingReceiptEnvelope, context)
}

/// Delegates one closed Dreamer ledger request to the canonical adapter
/// exactly once and maps the outcome through [`map_dreamer_dispatch_result`].
///
/// This is the single production Dreamer route used by the
/// [`StoreDispatchBackend`] implementation below: thin input/result/error
/// passthrough with no cache, job map, lease state, retry, or A-03
/// interpretation. Tests call this same function with a live adapter, so no
/// test-only substitute route exists.
pub(crate) async fn dispatch_dreamer_job(
    store: &impl CanonicalStoreClient,
    context: &RequestMeta,
    request: DurableJobRequest,
) -> Response {
    // Exact request and mutation identities from the admitted K0 shape, never
    // diagnostic text. The admitted operation id is the sole reconciliation
    // key for ambiguous outcomes.
    let failure_context = failure_context_for_operation(
        context,
        request.request_identity.operation.operation_id.clone(),
        request.request_identity.operation.idempotency_key.clone(),
    );
    match CanonicalStoreClient::dreamer_job(store, context, request.clone()).await {
        Ok(response) => map_dreamer_dispatch_result(&request, response, failure_context),
        Err(error) => map_store_error(error, failure_context),
    }
}

#[allow(async_fn_in_trait)]
pub trait StoreDispatchBackend: Send + Sync {
    async fn dispatch_request(&self, request: Request) -> Response;
}

pub async fn dispatch<B: StoreDispatchBackend + ?Sized>(backend: &B, request: Request) -> Response {
    backend.dispatch_request(request).await
}

impl StoreDispatchBackend for StoreComposition {
    async fn dispatch_request(&self, request: Request) -> Response {
        match request {
            Request::Health => match self.health().await {
                Ok(record) => Response::Health { record },
                Err(error) => map_store_error(error, StoreFailureIdentityContext::default()),
            },
            Request::Readiness => match self.readiness().await {
                Ok(receipt) => Response::Readiness { receipt },
                Err(error) => map_store_error(error, StoreFailureIdentityContext::default()),
            },
            Request::Named { request } => {
                let context = failure_context_for_fence(request.state_fence.clone());
                match self.named(request).await {
                    Ok(response) => Response::Named { response },
                    Err(error) => map_store_error(error, context),
                }
            }
            Request::Apply {
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            } => {
                let failure_context = failure_context_for_operation(
                    &context,
                    transition.identity.operation_id.clone(),
                    transition.identity.idempotency_key.clone(),
                );
                match Box::pin(self.apply(
                    &context,
                    transition,
                    expected_revision_heads,
                    expected_ordering_heads,
                ))
                .await
                {
                    Ok(receipt) => response_for_transaction_receipt(receipt, failure_context),
                    Err(error) => map_composition_error(error, failure_context),
                }
            }
            Request::Receipt { operation_id } => {
                let context = StoreFailureIdentityContext {
                    operation_id: Some(operation_id.clone()),
                    ..StoreFailureIdentityContext::default()
                };
                match self.receipt(operation_id).await {
                    Ok(receipt) => response_for_receipt_lookup(receipt, context),
                    Err(error) => map_store_error(error, context),
                }
            }
            // Issue #991: one authenticated reserved-write arm. The sealed
            // request is validated and delegated through the composition's
            // reserved-write operation only; an unsupported backend refuses
            // with a typed failure before any provider I/O and never falls
            // back to ordinary `Apply`.
            Request::ReservedWrite { request } => {
                let failure_context = failure_context_for_operation(
                    &request.context,
                    request.transition.identity.operation_id.clone(),
                    request.transition.identity.idempotency_key.clone(),
                );
                match self.apply_reserved_write(request).await {
                    Ok(receipt) => response_for_transaction_receipt(receipt, failure_context),
                    Err(error) => map_composition_error(error, failure_context),
                }
            }
            Request::RevisionHeads { keys } => match self.revision_heads(keys).await {
                Ok(heads) => Response::RevisionHeads { heads },
                Err(error) => map_store_error(error, StoreFailureIdentityContext::default()),
            },
            Request::OrderingHeads { scopes } => match self.ordering_heads(scopes).await {
                Ok(heads) => Response::OrderingHeads { heads },
                Err(error) => map_store_error(error, StoreFailureIdentityContext::default()),
            },
            Request::ValidationSnapshot => match self.validation_snapshot().await {
                Ok(snapshot) => Response::ValidationSnapshot { snapshot },
                Err(error) => map_store_error(error, StoreFailureIdentityContext::default()),
            },
            Request::Recovery { request } => {
                let result = CanonicalStoreClient::recovery(&self.store, request.clone()).await;
                map_recovery_dispatch_result(&request, result)
            }
            Request::InitializeGenesis { context, request } => {
                let result = CanonicalStoreClient::initialize_genesis(
                    &self.store,
                    &context,
                    request.clone(),
                )
                .await;
                map_genesis_dispatch_result(&context, &request, result)
            }
            Request::DreamerJob { context, request } => {
                // Boxed: the ledger request/response futures hold
                // multi-kilobyte canonical payloads across provider awaits.
                Box::pin(dispatch_dreamer_job(&self.store, &context, request.clone())).await
            }
        }
    }
}

#[cfg(test)]
mod reconcile_mapping_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_store_api::{
        CommitId, OperationId, OperationManifestDigest, Resubmission, ScopeId, TransitionClass,
        WriteReceiptStatus,
    };

    fn test_fence() -> eliot_contracts::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
        eliot_contracts::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn committed_looking_receipt_without_envelope() -> WriteReceipt {
        // Shape-valid terminal receipt that crossed the provider boundary
        // without proving its envelope: reconciliation state, never success.
        let fence = test_fence();
        WriteReceipt {
            operation_id: OperationId::new("op-reconcile").expect("operation id"),
            idempotency_key: "idem-reconcile".to_owned(),
            canonical_request_hash: "a".repeat(64),
            transition_class: TransitionClass::RecoverySchema,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(CommitId::new("commit-reconcile").expect("commit")),
            state_fence: fence,
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["genesis-seed".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: OperationManifestDigest::new("manifest-reconcile")
                .expect("manifest digest"),
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some("commit-sequence-0000000000000001".to_owned()),
            envelope: None,
        }
    }

    fn identity_context(operation: &str) -> StoreFailureIdentityContext {
        StoreFailureIdentityContext {
            operation_id: Some(OperationId::new(operation).expect("operation id")),
            ..StoreFailureIdentityContext::default()
        }
    }

    #[test]
    fn drop_after_send_reconciles_without_re_effect_or_success_claim() {
        // A drop after send leaves an envelope-less observation: the dispatch
        // boundary reports unknown outcome bound to the exact admitted
        // operation, never a success and never a not-attempted claim.
        let receipt = committed_looking_receipt_without_envelope();
        assert!(receipt.validate().is_ok(), "fixture receipt is shape-valid");
        let context = identity_context("op-reconcile");
        match response_for_receipt_lookup(Some(receipt), context) {
            Response::Failure { failure } => {
                assert_eq!(
                    failure.operation_id,
                    Some(OperationId::new("op-reconcile").expect("operation id"))
                );
                assert_eq!(
                    failure.disposition,
                    eliot_store_api::StoreFailureDisposition::UnknownOutcome
                );
                assert_eq!(
                    failure.mutation_disposition,
                    eliot_store_api::StoreMutationDisposition::Unknown
                );
                assert_eq!(
                    failure.retry_directive,
                    eliot_store_api::StoreRetryDirective::ReconcileExactOperation
                );
                failure.validate().expect("typed unknown failure validates");
            }
            Response::Receipt { .. } => panic!("envelope-less receipt must not report success"),
            other => panic!("unexpected dispatch response: {other:?}"),
        }
        // A missing receipt stays a valid empty lookup, not a failure.
        assert!(matches!(
            response_for_receipt_lookup(None, identity_context("op-absent")),
            Response::Receipt { receipt: None }
        ));
        let _ = ScopeId::new("scope-reconcile").expect("scope");
    }

    #[test]
    fn transaction_receipt_without_envelope_is_unknown_outcome() {
        let receipt = committed_looking_receipt_without_envelope();
        match response_for_transaction_receipt(receipt, identity_context("op-reconcile")) {
            Response::Failure { failure } => {
                assert_eq!(
                    failure.disposition,
                    eliot_store_api::StoreFailureDisposition::UnknownOutcome
                );
                failure.validate().expect("typed unknown failure validates");
            }
            Response::Transaction { .. } => {
                panic!("envelope-less transaction must not report success")
            }
            other => panic!("unexpected dispatch response: {other:?}"),
        }
    }
}

#[cfg(test)]
mod dreamer_dispatch_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_contracts::{ArtifactId, ClockReading, ProductId, RequestId, SourceId, TaskId};
    use eliot_protocol::dreamer_job::{DurableRequestIdentity, JobOperation, JobRole, JobState};
    use eliot_store_api::{
        OperationId, StoreFailureDisposition, StoreMutationDisposition, StoreRecoveryAction,
        StoreRetryDirective,
    };

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> eliot_contracts::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new(LINEAGE).expect("lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("seq")).expect("epoch");
        eliot_contracts::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn test_ctx(fence: &eliot_contracts::StateFence) -> RequestMeta {
        RequestMeta {
            request_id: RequestId::new("request-dreamer-s2").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-dreamer-s2").expect("product"),
            source_id: SourceId::new("source-dreamer-s2").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading {
                valid_time_ms: Some(1_000),
                known_time_ms: Some(1_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
        }
    }

    fn work_scope_json() -> serde_json::Value {
        serde_json::json!({
            "scope_id": "scope-dreamer-s2",
            "product_id": "product-dreamer-s2",
            "resource_generation": 1,
            "state_fence": serde_json::to_value(test_fence()).expect("fence json"),
        })
    }

    fn content_ref(revision: &str) -> serde_json::Value {
        serde_json::json!({
            "contract": {
                "name": "eliot.smart.dreamer.contracts",
                "version": {"major": 1, "minor": 0, "patch": 0},
                "shape_sha256": "0".repeat(64),
            },
            "source_revision": revision,
            "byte_length": 8,
            "sha256": "1".repeat(64),
            "artifact_id": format!("artifact-{revision}"),
        })
    }

    fn admission_json() -> serde_json::Value {
        let fence = serde_json::to_value(test_fence()).expect("fence json");
        serde_json::json!({
            "authority": {
                "authority_id": "kernel",
                "authority_owner": "kernel",
                "authority_epoch": {"lineage_id": LINEAGE, "sequence": 1},
                "state_fence": fence,
                "allowed_effect": "CANDIDATE",
                "proof_ceiling": "CANDIDATE_ARTIFACT",
            },
            "requester_principal": "requester-s2",
            "session": null,
            "scope": work_scope_json(),
            "capability": "dreamer.submit",
            "route_class": "bounded",
            "budget_units": 1,
            "deadline_unix_ms": 600_000,
            "validity_epoch": {"lineage_id": LINEAGE, "sequence": 1},
            "resource_generation": 1,
            "admission_receipt": "admission-s2",
        })
    }

    fn submit_operation(job: &str, attempt: &str) -> JobOperation {
        let submission: eliot_protocol::dreamer_job::JobSubmission =
            serde_json::from_value(serde_json::json!({
                "job_id": job,
                "attempt_id": attempt,
                "work_scope": work_scope_json(),
                "semantic_input": content_ref("input-s2"),
                "output_contract": content_ref("output-s2"),
                "admission": admission_json(),
                "cancellation_id": "cancel-s2",
            }))
            .expect("submission");
        JobOperation::Submit {
            submission: Box::new(submission),
        }
    }

    fn renew_operation(job: &str, attempt: &str) -> JobOperation {
        let fence = serde_json::to_value(test_fence()).expect("fence json");
        let lease: eliot_protocol::dreamer_job::JobLease =
            serde_json::from_value(serde_json::json!({
                "job_id": job,
                "attempt_id": attempt,
                "lease_id": {
                    "namespace": "eliot.governor.work-lease",
                    "revision": "v1",
                    "value": "lease-s2"
                },
                "owner_artifact_id": "worker-s2",
                "resource_generation": 1,
                "state_fence": fence,
                "issued_at_unix_ms": 10,
                "expires_at_unix_ms": 100_000,
                "revision": 1
            }))
            .expect("lease");
        JobOperation::Renew {
            lease,
            now_unix_ms: 2_000,
        }
    }

    /// Binds one closed operation to fresh transport correlation plus stable
    /// mutation identity with a recomputed canonical hash.
    fn make_request(
        ctx: &RequestMeta,
        operation: JobOperation,
        role: JobRole,
        operation_id: &str,
        idempotency: &str,
        transport_key: &str,
    ) -> DurableJobRequest {
        let kind = operation.kind().as_str().to_owned();
        let ctx_json = serde_json::to_value(ctx).expect("ctx json");
        let fence = serde_json::to_value(test_fence()).expect("fence json");
        let mut identity: DurableRequestIdentity = serde_json::from_value(serde_json::json!({
            "request": {
                "request": {"metadata": ctx_json, "state_fence": fence.clone()},
                "idempotency_key": transport_key,
                "deadline_unix_ms": 600_000,
                "cancellation_id": "cancel-s2",
            },
            "operation": {
                "operation_id": operation_id,
                "request_id": "originating-s2",
                "idempotency_key": idempotency,
                "operation_kind": kind,
                "effect": "CANDIDATE",
                "state_fence": fence,
            },
            "canonical_request_hash": "0".repeat(64),
        }))
        .expect("identity");
        identity.canonical_request_hash = DurableRequestIdentity::digest_for(
            &identity.operation,
            &identity.request,
            &operation,
            role,
        )
        .expect("hash");
        let request = DurableJobRequest {
            request_identity: identity,
            role,
            operation,
        };
        request.validate().expect("request validates");
        request
    }

    fn submit_request(ctx: &RequestMeta) -> DurableJobRequest {
        make_request(
            ctx,
            submit_operation("job-s2", "attempt-s2"),
            JobRole::Requester,
            "op-submit-s2",
            "idem-submit-s2",
            "transport-submit-s2",
        )
    }

    /// Builds the exact success answer the S1 ledger returns for the submit
    /// above: identity echo, job/scope binding, first revision, committed
    /// disposition with an owner receipt.
    fn submit_response(request: &DurableJobRequest) -> DurableJobResponse {
        serde_json::from_value(serde_json::json!({
            "request_identity": serde_json::to_value(&request.request_identity).expect("identity json"),
            "job_id": "job-s2",
            "attempt_id": "attempt-s2",
            "scope": work_scope_json(),
            "revision": 1,
            "state": "QUEUED",
            "disposition": "COMMITTED",
            "receipt_id": "dreamer-receipt-op-submit-s2",
            "lease": null,
            "checkpoint": null,
            "result_under_verification": null,
            "outcome": null,
            "selection_coverage": [],
            "selection_frontier": null,
        }))
        .expect("response")
    }

    fn failure_context_for(
        ctx: &RequestMeta,
        operation_id: &str,
        idempotency_key: &str,
    ) -> StoreFailureIdentityContext {
        failure_context_for_operation(
            ctx,
            OperationId::new(operation_id).expect("operation id"),
            idempotency_key.to_owned(),
        )
    }

    #[test]
    fn dreamer_identity_checked_success_passes_response_through() {
        let fence = test_fence();
        let ctx = test_ctx(&fence);
        let request = submit_request(&ctx);
        let response = submit_response(&request);
        response
            .validate_for(&request)
            .expect("fixture answers its request");
        match map_dreamer_dispatch_result(
            &request,
            response,
            failure_context_for(&ctx, "op-submit-s2", "idem-submit-s2"),
        ) {
            Response::DreamerJob { response } => {
                assert_eq!(response.job_id.as_str(), "job-s2");
                assert_eq!(response.attempt_id.as_str(), "attempt-s2");
                assert_eq!(response.state, JobState::Queued);
                assert_eq!(response.revision, 1);
                assert!(response.receipt_id.is_some(), "commit keeps its receipt");
                response
                    .validate_for(&request)
                    .expect("dispatched response still answers its request");
            }
            other => panic!("identity-checked success must pass through: {other:?}"),
        }
    }

    #[test]
    fn dreamer_foreign_response_is_typed_unknown_without_retry() {
        // The backend answered for a different job: the mutation outcome is
        // ambiguous, so the seam reports unknown bound to the admitted
        // operation — never success and never a blind same-identity retry.
        let fence = test_fence();
        let ctx = test_ctx(&fence);
        let request = submit_request(&ctx);
        let mut response = submit_response(&request);
        response.job_id = TaskId::new("job-other").expect("job");
        assert!(response.validate_for(&request).is_err());
        match map_dreamer_dispatch_result(
            &request,
            response,
            failure_context_for(&ctx, "op-submit-s2", "idem-submit-s2"),
        ) {
            Response::Failure { failure } => {
                assert_eq!(
                    failure.operation_id,
                    Some(OperationId::new("op-submit-s2").expect("operation id"))
                );
                assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);
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
                assert_ne!(
                    failure.retry_directive,
                    StoreRetryDirective::RetrySameIdentityAfterBackoff,
                    "ambiguity must not become a retryable unavailable"
                );
                failure.validate().expect("typed unknown failure validates");
            }
            other => panic!("foreign answer must not become success: {other:?}"),
        }
    }

    #[test]
    fn dreamer_committed_claim_without_receipt_is_unknown() {
        // A committed mutation without an owner receipt is an incomplete
        // proof: it cannot become success.
        let fence = test_fence();
        let ctx = test_ctx(&fence);
        let request = submit_request(&ctx);
        let mut response = submit_response(&request);
        response.receipt_id = None;
        assert!(response.validate_for(&request).is_err());
        match map_dreamer_dispatch_result(
            &request,
            response,
            failure_context_for(&ctx, "op-submit-s2", "idem-submit-s2"),
        ) {
            Response::Failure { failure } => {
                assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);
                assert_eq!(
                    failure.retry_directive,
                    StoreRetryDirective::ReconcileExactOperation
                );
                failure.validate().expect("typed unknown failure validates");
            }
            other => panic!("receipt-less commit must not become success: {other:?}"),
        }
    }

    #[test]
    fn dreamer_deterministic_errors_pass_through_unchanged() {
        // S2 preserves the S1 typed contract: a revision conflict stays a
        // proven-not-applied conflict (never retried under the same
        // identity), and an unadvertised operation stays unsupported.
        let fence = test_fence();
        let ctx = test_ctx(&fence);
        let context = failure_context_for(&ctx, "op-submit-s2", "idem-submit-s2");
        match map_store_error(StoreError::RevisionConflict, context.clone()) {
            Response::Failure { failure } => {
                assert_eq!(failure.disposition, StoreFailureDisposition::Conflict);
                assert_eq!(
                    failure.mutation_disposition,
                    StoreMutationDisposition::NotAttempted
                );
                assert_eq!(
                    failure.retry_directive,
                    StoreRetryDirective::NewIdentityAfterCondition
                );
                assert_eq!(
                    failure.recovery_action,
                    StoreRecoveryAction::RefreshRevisionHeads
                );
                failure.validate().expect("typed conflict validates");
            }
            other => panic!("conflict must stay a conflict: {other:?}"),
        }
        match map_store_error(StoreError::UnknownOperation, context) {
            Response::Failure { failure } => {
                assert_eq!(failure.disposition, StoreFailureDisposition::Unsupported);
                assert_eq!(
                    failure.mutation_disposition,
                    StoreMutationDisposition::NotAttempted
                );
                assert_eq!(failure.retry_directive, StoreRetryDirective::DoNotRetry);
                failure.validate().expect("typed unsupported validates");
            }
            other => panic!("unadvertised operation must stay unsupported: {other:?}"),
        }
    }

    #[test]
    fn dreamer_ambiguous_adapter_error_stays_reconciling_unknown() {
        // The S1 encoding of an ambiguous provider outcome
        // (`MissingReceiptEnvelope`) keeps the reconcile directive at the
        // dispatch boundary: uncertainty is never translated to a retryable
        // unavailable.
        let fence = test_fence();
        let ctx = test_ctx(&fence);
        match map_store_error(
            StoreError::MissingReceiptEnvelope,
            failure_context_for(&ctx, "op-submit-s2", "idem-submit-s2"),
        ) {
            Response::Failure { failure } => {
                assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);
                assert_eq!(
                    failure.mutation_disposition,
                    StoreMutationDisposition::Unknown
                );
                assert_eq!(
                    failure.retry_directive,
                    StoreRetryDirective::ReconcileExactOperation
                );
                failure.validate().expect("typed unknown failure validates");
            }
            other => panic!("ambiguous outcome must stay unknown: {other:?}"),
        }
    }

    /// Isolated provider executable for the live dispatch proof. Overridable
    /// for local runs; the default is the pinned local installation.
    const TEST_SURREAL_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";

    fn surreal_exe() -> std::path::PathBuf {
        std::env::var("ELIOT_TEST_SURREAL_EXE").map_or_else(
            |_| std::path::PathBuf::from(TEST_SURREAL_EXE),
            std::path::PathBuf::from,
        )
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("loopback")
            .local_addr()
            .expect("port")
            .port()
    }

    /// Best-effort scratch-root cleanup for provider-backed dispatch tests.
    struct TempRoot {
        path: std::path::PathBuf,
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Builds a shape-valid but never-connected adapter: the provider binary
    /// is staged and the lease retained, but no provider is spawned and
    /// nothing listens on the configured endpoint.
    fn unconnected_adapter(
        root: &std::path::Path,
        port: u16,
    ) -> eliot_store_surreal_adapter::SurrealStoreAdapter {
        use eliot_store_surreal_adapter::{
            PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
        };
        let bin = root.join("bin");
        let data = root.join("store").join("data");
        let work = root.join("store").join("work");
        let tmp = root.join("store").join("tmp");
        for dir in [&bin, &data, &work, &tmp] {
            std::fs::create_dir_all(dir).expect("test dirs");
        }
        let source_exe = surreal_exe();
        assert!(
            source_exe.is_file(),
            "pinned test provider is absent: {}",
            source_exe.display()
        );
        let exe = bin.join("surreal.exe");
        std::fs::copy(&source_exe, &exe).expect("stage provider");
        let bytes = std::fs::read(&exe).expect("read staged provider");
        let digest = eliot_store_api::sha256_hex(&bytes);
        let platform =
            eliot_platform_windows::WindowsPlatform::new(root.to_path_buf()).expect("platform");
        let lease = platform
            .retain_process_path_lease(&exe, &work, &digest)
            .expect("process lease");
        let bind = format!("127.0.0.1:{port}");
        let mut config = SurrealAdapterConfig {
            endpoint: format!("ws://{bind}/rpc"),
            namespace: "eliot".to_owned(),
            database: "dreamer_s2_dispatch".to_owned(),
            username: "dreamer-test".to_owned(),
            password: secrecy::SecretString::new("dreamer-test-secret".into()),
            provider_bind_address: bind,
            installation_id: "installation-test-s2".to_owned(),
            installation_profile: "portable_dev".to_owned(),
            runtime_state_roots_digest: "a".repeat(64),
            provider_executable_path: exe.to_string_lossy().into_owned(),
            provider_artifact_digest: digest,
            provider_arguments: Vec::new(),
            store_data_root: data.to_string_lossy().into_owned(),
            store_work_root: work.to_string_lossy().into_owned(),
            store_temp_root: tmp.to_string_lossy().into_owned(),
            connect_timeout_ms: 5_000,
            query_timeout_ms: 5_000,
            expected_provider_major: PINNED_SURREALDB_MAJOR,
            expected_schema_generation: SchemaGeneration::v2(),
        };
        config.provider_arguments = config.expected_provider_arguments();
        SurrealStoreAdapter::new(config, lease).expect("adapter")
    }

    #[tokio::test]
    async fn dreamer_unsupported_operation_rejected_without_provider_write() {
        // `Renew` is a well-shaped K0 operation with a permitting role, but
        // S1 explicitly leaves it unadvertised. The adapter rejects it before
        // any provider I/O; the endpoint here has no listener, so any
        // attempted write would surface as `Unavailable` instead of the
        // asserted `Unsupported`.
        let fence = test_fence();
        let ctx = test_ctx(&fence);
        let request = make_request(
            &ctx,
            renew_operation("job-s2", "attempt-s2"),
            JobRole::Worker,
            "op-renew-s2",
            "idem-renew-s2",
            "transport-renew-s2",
        );
        let root_path = std::env::temp_dir().join(format!(
            "eliot-store-s2-dreamer-nowrite-{}",
            std::process::id()
        ));
        let _root = TempRoot {
            path: root_path.clone(),
        };
        let adapter = unconnected_adapter(&root_path, free_port());
        match dispatch_dreamer_job(&adapter, &ctx, request).await {
            Response::Failure { failure } => {
                assert_eq!(
                    failure.operation_id,
                    Some(OperationId::new("op-renew-s2").expect("operation id"))
                );
                assert_eq!(failure.disposition, StoreFailureDisposition::Unsupported);
                assert_eq!(
                    failure.mutation_disposition,
                    StoreMutationDisposition::NotAttempted
                );
                assert_eq!(failure.retry_directive, StoreRetryDirective::DoNotRetry);
                failure.validate().expect("typed unsupported validates");
            }
            other => panic!("unadvertised operation must not write: {other:?}"),
        }
    }

    /// Provisions the initial root credential inside a fresh `SurrealKV` data
    /// root, mirroring installation provisioning: a short-lived preparation
    /// provider creates the initial root user, then releases the port/files
    /// before the adapter's own provider spawns.
    fn prepare_initial_root_user(
        exe: &std::path::Path,
        bind: &str,
        data: &std::path::Path,
        work: &std::path::Path,
        tmp: &std::path::Path,
    ) {
        use secrecy::ExposeSecret;
        use std::process::Stdio;
        use std::time::Duration;
        let password = secrecy::SecretString::new("dreamer-test-secret".into());
        let data_url = format!("surrealkv://{}", data.to_string_lossy().replace('\\', "/"));
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let mut child = std::process::Command::new(exe)
            .args([
                "start",
                "--no-banner",
                "--bind",
                bind,
                "--username",
                "dreamer-test",
                "--password",
                password.expose_secret(),
                "--temporary-directory",
                &tmp.to_string_lossy(),
                "--log-file-enabled",
                "--log-file-path",
                &work.to_string_lossy(),
                "--log-file-name",
                "surrealdb.log",
                &data_url,
            ])
            .current_dir(work)
            .env_clear()
            .env("SystemRoot", &system_root)
            .env("WINDIR", &system_root)
            .env("TEMP", tmp)
            .env("TMP", tmp)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("preparation provider");
        let deadline = std::time::Instant::now() + Duration::from_mins(1);
        loop {
            if std::net::TcpStream::connect(bind).is_ok() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("preparation provider never bound {bind}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_secs(2));
        child.kill().expect("stop preparation provider");
        let _ = child.wait();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::net::TcpStream::connect(bind).is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "preparation provider never released {bind}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    #[tokio::test]
    async fn dreamer_dispatch_submit_then_status_reads_back_queued_job() {
        // S2 acceptance through the single production delegation: an actual
        // Store-process client submits a job and reads the queued record back
        // from the real Surreal-backed adapter. No test-only route is used:
        // both calls go through `dispatch_dreamer_job`, the exact function
        // the `StoreDispatchBackend` arm invokes.
        let fence = test_fence();
        let ctx = test_ctx(&fence);
        let root_path = std::env::temp_dir().join(format!(
            "eliot-store-s2-dreamer-live-{}-{}",
            std::process::id(),
            free_port()
        ));
        let _root = TempRoot {
            path: root_path.clone(),
        };
        let port = free_port();
        let adapter = unconnected_adapter(&root_path, port);
        let bind = format!("127.0.0.1:{port}");
        let data = root_path.join("store").join("data");
        let work = root_path.join("store").join("work");
        let tmp = root_path.join("store").join("tmp");
        let exe = root_path.join("bin").join("surreal.exe");
        prepare_initial_root_user(&exe, &bind, &data, &work, &tmp);
        adapter.connect().await.expect("provider connect");
        let migration = eliot_store_surreal_adapter::SurrealStoreAdapter::v2_baseline_migration();
        if let Err(error) = adapter
            .apply_migration(&migration, &ctx.clock, &fence)
            .await
        {
            panic!("baseline migration: {error:?}");
        }

        let submit = make_request(
            &ctx,
            submit_operation("job-s2-live", "attempt-s2-live"),
            JobRole::Requester,
            "op-submit-s2-live",
            "idem-submit-s2-live",
            "transport-submit-s2-live",
        );
        let revision = match dispatch_dreamer_job(&adapter, &ctx, submit.clone()).await {
            Response::DreamerJob { response } => {
                response.validate_for(&submit).expect("submit answers");
                assert_eq!(response.job_id.as_str(), "job-s2-live");
                assert_eq!(response.attempt_id.as_str(), "attempt-s2-live");
                assert_eq!(response.state, JobState::Queued);
                assert!(response.receipt_id.is_some(), "commit keeps its receipt");
                response.revision
            }
            other => panic!("submit must persist a queued job: {other:?}"),
        };
        assert_eq!(revision, 1, "first submit creates the first revision");

        let status_ctx = RequestMeta {
            request_id: RequestId::new("request-dreamer-s2-status").expect("request id"),
            ..test_ctx(&fence)
        };
        let status = make_request(
            &status_ctx,
            JobOperation::Status {
                job_id: TaskId::new("job-s2-live").expect("job"),
                attempt_id: ArtifactId::new("attempt-s2-live").expect("attempt"),
                expected_revision: revision,
                expected_fence: fence.clone(),
            },
            JobRole::Requester,
            "op-status-s2-live",
            "idem-status-s2-live",
            "transport-status-s2-live",
        );
        match dispatch_dreamer_job(&adapter, &status_ctx, status.clone()).await {
            Response::DreamerJob { response } => {
                response.validate_for(&status).expect("status answers");
                assert_eq!(response.job_id.as_str(), "job-s2-live");
                assert_eq!(response.attempt_id.as_str(), "attempt-s2-live");
                assert_eq!(response.revision, revision);
                assert_eq!(response.state, JobState::Queued);
                assert!(
                    response.disposition.is_none(),
                    "status is a pure observation without mutation disposition"
                );
            }
            other => panic!("status must read back the queued job: {other:?}"),
        }
    }
}
