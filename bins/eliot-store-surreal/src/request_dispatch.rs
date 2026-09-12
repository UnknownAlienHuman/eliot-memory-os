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
                match self
                    .apply(
                        &context,
                        transition,
                        expected_revision_heads,
                        expected_ordering_heads,
                    )
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
        }
    }
}
