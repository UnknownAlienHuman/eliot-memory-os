//! Closed request dispatch seam for `eliot-store-surreal`.
//!
//! Architecture: A12.3 One governed write path, A13.2 Kernel and failure domains,
//! ARCH-AUTH-01 authority/fence-bound execution, ARCH-SEC-02 session/capability boundary,
//! ARCH-RES-01 bounded closed dispatch.
//! Implementation: I5.1 provider-owned store seam, I5.9 explicit receipt reconciliation,
//! I5.11 closed Request catalogue, B.2 bounded error surface, I14.21 deterministic dispatch,
//! I2.2 crate ownership, I2.23 seam cohesion.
//!
//! Store remains the durable owner. This module only dispatches already
//! session-validated closed `Request`s, preserves exact operation identity and
//! `UnknownOutcome` without fabricating success, and never interprets Governor
//! semantics, mints authority, or owns capability/session admission (root remains
//! responsible for handshake, replay, fence and capability validation).

use eliot_store_api::CanonicalStoreClient;
use eliot_store_api::StoreError;
use eliot_store_api::StoreGenesisRequest;
use eliot_store_api::StoreRecoverySnapshot;
use eliot_store_api::WriteReceipt;

use crate::Request;
use crate::Response;
use crate::StoreComposition;
use crate::StoreCompositionError;

pub(crate) const UNKNOWN_GENESIS_REASON: &str =
    "genesis receipt envelope is missing; reconcile by exact operation identity";

pub(crate) fn map_recovery_dispatch_result(
    result: Result<StoreRecoverySnapshot, StoreError>,
) -> Response {
    match result {
        Ok(snapshot) => Response::Recovery { snapshot },
        Err(error) => Response::Error {
            error: error.to_string(),
        },
    }
}

pub(crate) fn map_genesis_dispatch_result(
    request: StoreGenesisRequest,
    result: Result<WriteReceipt, StoreError>,
) -> Response {
    match result {
        Ok(receipt) => Response::Genesis { receipt },
        Err(StoreError::MissingReceiptEnvelope) => Response::Unknown {
            operation_id: request.operation_id,
            reason: UNKNOWN_GENESIS_REASON.to_owned(),
        },
        Err(error) => Response::Error {
            error: error.to_string(),
        },
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
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            Request::Readiness => match self.readiness().await {
                Ok(receipt) => Response::Readiness { receipt },
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            Request::Named { request } => match self.named(request).await {
                Ok(response) => Response::Named { response },
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            Request::Apply {
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            } => match self
                .apply(
                    &context,
                    transition,
                    expected_revision_heads,
                    expected_ordering_heads,
                )
                .await
            {
                Ok(receipt) => Response::from_transaction_receipt(receipt),
                Err(StoreCompositionError::UnknownOutcome {
                    operation_id,
                    reason,
                }) => Response::Unknown {
                    operation_id,
                    reason,
                },
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            Request::Receipt { operation_id } => match self.receipt(operation_id).await {
                Ok(receipt) => Response::from_receipt(receipt),
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            Request::RevisionHeads { keys } => match self.revision_heads(keys).await {
                Ok(heads) => Response::RevisionHeads { heads },
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            Request::OrderingHeads { scopes } => match self.ordering_heads(scopes).await {
                Ok(heads) => Response::OrderingHeads { heads },
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            Request::ValidationSnapshot => match self.validation_snapshot().await {
                Ok(snapshot) => Response::ValidationSnapshot { snapshot },
                Err(error) => Response::Error {
                    error: error.to_string(),
                },
            },
            Request::Recovery { request } => map_recovery_dispatch_result(
                CanonicalStoreClient::recovery(&self.store, request).await,
            ),
            Request::InitializeGenesis { context, request } => {
                let result = CanonicalStoreClient::initialize_genesis(
                    &self.store,
                    &context,
                    request.clone(),
                )
                .await;
                map_genesis_dispatch_result(request, result)
            }
        }
    }
}
