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

fn map_store_error(error: StoreError, context: StoreFailureIdentityContext) -> Response {
    match StoreFailure::from_store_error(error, context) {
        Ok(failure) => Response::Failure { failure },
        Err(error) => Response::Error {
            error: format!("store failure contract mapping failed: {error}"),
        },
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
        StoreCompositionError::UnknownOutcome { .. } => {
            match StoreFailure::from_provider_unknown_outcome(&context) {
                Ok(failure) => Response::Failure { failure },
                Err(error) => Response::Error {
                    error: format!("store failure contract mapping failed: {error}"),
                },
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
                    Ok(receipt) => Response::from_transaction_receipt(receipt),
                    Err(error) => map_composition_error(error, failure_context),
                }
            }
            Request::Receipt { operation_id } => {
                let context = StoreFailureIdentityContext {
                    operation_id: Some(operation_id.clone()),
                    ..StoreFailureIdentityContext::default()
                };
                match self.receipt(operation_id).await {
                    Ok(receipt) => Response::from_receipt(receipt),
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
