//! Kernel-owned gateway for applying an already prepared canonical transition.

use std::sync::{Arc, Mutex};

use eliot_contracts::{ContractId, RequestMetadata};
use eliot_kernel_core::GenerationRoute;
use eliot_store_api::{
    CanonicalStoreClient, OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation,
    StoreError, WriteReceipt,
};
use thiserror::Error;

use crate::{KernelService, KernelServiceError};

/// Failure from the Kernel transition gateway.
#[derive(Debug, Error)]
pub enum PreparedTransitionError {
    /// The Kernel service is not ready or has been fenced.
    #[error("Kernel admission: {0}")]
    Admission(#[from] KernelServiceError),
    /// The caller or route did not match the current Kernel binding.
    #[error("Kernel transition binding: {0}")]
    Binding(&'static str),
    /// The canonical store rejected or could not establish the outcome.
    #[error("canonical store: {0}")]
    Store(#[from] StoreError),
}

/// Sole Kernel-owned gateway from a prepared transition to the canonical store.
///
/// The gateway acquires the Kernel control reserve before forwarding and holds
/// that lease for the complete store call.  It never prepares transitions,
/// writes directly, or creates a second store client/writer.
pub struct PreparedTransitionGateway<C> {
    service: Arc<Mutex<KernelService>>,
    store: Arc<C>,
    route: GenerationRoute,
    caller: ContractId,
}

impl<C> std::fmt::Debug for PreparedTransitionGateway<C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedTransitionGateway")
            .field("route", &self.route)
            .field("caller", &self.caller)
            .finish_non_exhaustive()
    }
}

impl<C: CanonicalStoreClient + 'static> PreparedTransitionGateway<C> {
    /// Creates a gateway bound to one Kernel route and one caller identity.
    pub fn new(
        service: Arc<Mutex<KernelService>>,
        store: Arc<C>,
        route: GenerationRoute,
        caller: ContractId,
    ) -> Self {
        Self {
            service,
            store,
            route,
            caller,
        }
    }

    /// Applies one prepared transition after exact Kernel admission checks.
    pub async fn apply(
        &self,
        context: &RequestMetadata,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, PreparedTransitionError> {
        context.validate().map_err(|error| {
            PreparedTransitionError::Binding(match error {
                eliot_contracts::ContractError::MissingRequestId => "request_id",
                _ => "request_metadata",
            })
        })?;
        transition.validate()?;
        if context.source_id.as_str() != self.caller.as_str() {
            return Err(PreparedTransitionError::Binding("caller"));
        }
        if transition.state_fence != context.state_fence {
            return Err(PreparedTransitionError::Binding("state_fence"));
        }

        let lease = {
            let service = self
                .service
                .lock()
                .map_err(|_| PreparedTransitionError::Binding("kernel_service_poisoned"))?;
            if service.generation_fenced() {
                return Err(PreparedTransitionError::Admission(
                    KernelServiceError::GenerationFenced,
                ));
            }
            if self.route.authority_epoch() != service.authority_epoch()
                || self.route.active_generation() != transition.state_fence.resource_generation
            {
                return Err(PreparedTransitionError::Binding("route"));
            }
            let lease = service.acquire_admission()?;
            if lease.authority_epoch() != transition.state_fence.authority_epoch {
                return Err(PreparedTransitionError::Binding("authority_epoch"));
            }
            lease
        };

        let result = self
            .store
            .apply_prepared(
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await;
        drop(lease);
        result.map_err(PreparedTransitionError::Store)
    }

    /// Returns the immutable route binding held by this gateway.
    #[must_use]
    pub fn route(&self) -> &GenerationRoute {
        &self.route
    }
}
