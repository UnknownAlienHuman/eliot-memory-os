//! Kernel-owned, store-neutral S-03 EBP client.
//!
//! The client owns only authenticated EBP framing and closed store-api
//! operations.  It never opens a provider SDK, constructs a query, mints
//! authority, or decides completion.  An uncertain apply is reconciled only
//! by the exact operation identity carried by the prepared transition.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, atomic::AtomicU64};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{ArtifactId, ContractId, ContractVersion, StateFence};
use eliot_ipc::{DeliveryOutcome, TransportError, TransportLimits};
use eliot_protocol::{ClientHello, Frame, ProtocolRange, ProtocolVersion, ServerHello};
use eliot_runtime_contracts::{ModuleContract, ModuleGeneration, ModuleGenerationState};
use eliot_store_api::{
    CAPABILITIES, CanonicalStoreClient, CanonicalValidationSnapshot, EFFECTS, NamedReadOperation,
    NamedReadRequest, NamedReadResponse, OperationId, OrderingHead, OrderingHeadExpectation,
    OrderingScopeId, PreparedTransition, ReadConsistency, RecoveryRecordKey, RequestMeta,
    RevisionHead, RevisionHeadExpectation, RevisionKey, ScopeId, ScopeRevisionView, StoreError,
    StoreGenesisRequest, StoreHealth, StoreRecoveryRequest, StoreRecoverySnapshot, StoreRequest,
    StoreResponse, StoreWireError, WriteReceipt, validate_genesis_receipt_envelope,
};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{HostStoreBootstrapRequirement, STORE_MODULE_IDENTITY};

#[path = "store_exchange.rs"]
mod store_exchange;

use store_exchange::RequestFailure;

/// Transport boundary used by the neutral EBP store client.
///
/// Implementations must establish the platform authentication proof before
/// returning `Ok(())`; a pipe name or process id alone is insufficient.
#[allow(async_fn_in_trait)]
pub trait EbpStoreTransport: Send {
    /// Confirms that the lower transport has authenticated the peer.
    fn ensure_authenticated(
        &self,
        requirement: &HostStoreBootstrapRequirement,
    ) -> Result<(), StoreClientError>;

    /// Sends one bounded EBP frame.
    async fn send_frame(
        &mut self,
        frame: &Frame,
        limits: TransportLimits,
    ) -> Result<DeliveryOutcome, StoreClientError>;

    /// Receives one bounded EBP frame.
    async fn receive_frame(&mut self, limits: TransportLimits) -> Result<Frame, StoreClientError>;
}

/// Client-side failures before a canonical store receipt exists.
#[derive(Debug, Error)]
pub enum StoreClientError {
    /// Transport or peer authentication failed.
    #[error("store transport: {0}")]
    Transport(String),
    /// The store handshake or response violated the closed contract.
    #[error("store EBP contract: {0}")]
    Contract(String),
    /// The store returned an application-level failure.
    #[error("store contract: {0}")]
    Store(#[from] StoreError),
}

impl From<TransportError> for StoreClientError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error.to_string())
    }
}

impl From<StoreWireError> for StoreClientError {
    fn from(error: StoreWireError) -> Self {
        Self::Contract(error.to_string())
    }
}

/// Authenticated neutral S-03 EBP client implementing the canonical store API.
pub struct EbpCanonicalStoreClient<T> {
    transport: Arc<Mutex<T>>,
    requirement: HostStoreBootstrapRequirement,
    protocol_version: ProtocolVersion,
    limits: TransportLimits,
    request_counter: AtomicU64,
}

impl<T> std::fmt::Debug for EbpCanonicalStoreClient<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EbpCanonicalStoreClient")
            .field("connection_id", &self.requirement.connection_id)
            .field("store_generation", &self.requirement.store_generation)
            .field("route_identity", &self.requirement.route_identity)
            .field("protocol_version", &self.protocol_version)
            .finish_non_exhaustive()
    }
}

impl<T: EbpStoreTransport + 'static> EbpCanonicalStoreClient<T> {
    /// Completes the authenticated EBP handshake and schema-readiness check.
    pub async fn connect(
        mut transport: T,
        requirement: HostStoreBootstrapRequirement,
    ) -> Result<Self, StoreClientError> {
        requirement
            .validate()
            .map_err(|error| StoreClientError::Contract(error.to_string()))?;
        transport.ensure_authenticated(&requirement)?;
        let hello = client_hello(&requirement)?;
        let limits = TransportLimits::default();
        let hello_frame =
            eliot_ipc::client_hello_frame(requirement.connection_id.as_str(), &hello)?;
        let outcome = transport.send_frame(&hello_frame, limits).await?;
        if outcome != DeliveryOutcome::Delivered {
            return Err(StoreClientError::Transport(
                "store handshake crossed an unknown delivery boundary".to_owned(),
            ));
        }
        let response = transport.receive_frame(limits).await?;
        let server = decode_server_hello(&response, &requirement)?;
        let client = Self {
            transport: Arc::new(Mutex::new(transport)),
            requirement,
            protocol_version: server.selected_protocol,
            limits,
            request_counter: AtomicU64::new(1),
        };
        client.verify_readiness().await?;
        Ok(client)
    }

    /// Returns the exact Host-approved bootstrap binding.
    #[must_use]
    pub const fn requirement(&self) -> &HostStoreBootstrapRequirement {
        &self.requirement
    }

    async fn verify_readiness(&self) -> Result<(), StoreClientError> {
        let response = self
            .execute_raw(StoreRequest::Readiness, None, "store-readiness")
            .await
            .map_err(|error| StoreClientError::Store(error.into_store_error()))?;
        let StoreResponse::Readiness { receipt } = response else {
            return Err(StoreClientError::Contract(
                "store readiness response was not Readiness".to_owned(),
            ));
        };
        receipt.validate()?;
        if receipt.status != eliot_store_api::ReadinessStatus::Ready
            || receipt.expected_generation.is_none()
            || receipt.observed_generation.is_none()
        {
            return Err(StoreClientError::Contract(
                "store schema generation is not the Host-approved ready generation".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_requirement_fence(&self, observed: &StateFence) -> Result<(), StoreError> {
        if observed != &self.requirement.state_fence
            || observed.resource_generation != self.requirement.store_generation
            || observed.authority_epoch != self.requirement.authority_epoch()
        {
            return Err(StoreError::FenceMismatch);
        }
        Ok(())
    }

    fn validate_recovery_snapshot(
        &self,
        request: &StoreRecoveryRequest,
        snapshot: &StoreRecoverySnapshot,
    ) -> Result<(), StoreError> {
        snapshot.validate()?;
        self.validate_requirement_fence(&request.state_fence)?;
        self.validate_requirement_fence(&snapshot.state_fence)?;

        let requested_keys = request.records.iter().cloned().collect::<BTreeSet<_>>();
        let returned_keys = snapshot
            .owner_records
            .iter()
            .map(eliot_store_api::RecoveryRecord::record_key)
            .collect::<BTreeSet<RecoveryRecordKey>>();
        if snapshot.owner_records.len() != request.records.len() || returned_keys != requested_keys
        {
            return Err(StoreError::IdentityConflict);
        }
        if !request.include_jobs && !snapshot.job_records.is_empty() {
            return Err(StoreError::InvalidField {
                field: "recovery.job_records",
                reason: "jobs were not requested",
            });
        }
        if !request.include_receipts && !snapshot.receipts.is_empty() {
            return Err(StoreError::InvalidField {
                field: "recovery.receipts",
                reason: "receipts were not requested",
            });
        }
        Ok(())
    }

    fn validate_genesis_receipt(
        &self,
        context: &RequestMeta,
        request: &StoreGenesisRequest,
        receipt: &WriteReceipt,
    ) -> Result<(), StoreError> {
        self.validate_requirement_fence(&context.state_fence)?;
        self.validate_requirement_fence(&request.state_fence)?;
        if receipt.operation_id != request.operation_id
            || receipt.idempotency_key != request.idempotency_key
            || receipt.canonical_request_hash != request.canonical_request_hash
        {
            return Err(StoreError::IdentityConflict);
        }
        self.validate_requirement_fence(&receipt.state_fence)?;
        validate_genesis_receipt_envelope(context, request, receipt)
    }

    async fn reconcile_genesis(
        &self,
        context: &RequestMeta,
        request: &StoreGenesisRequest,
    ) -> Result<WriteReceipt, StoreError> {
        let receipt = self.receipt_exact(request.operation_id.clone()).await?;
        self.validate_genesis_receipt(context, request, &receipt)?;
        Ok(receipt)
    }
}

impl<T: EbpStoreTransport + 'static> CanonicalStoreClient for EbpCanonicalStoreClient<T> {
    async fn apply_prepared(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        transition.validate()?;
        ctx.validate().map_err(StoreError::Foundation)?;
        if ctx.state_fence != self.requirement.state_fence
            || transition.state_fence != self.requirement.state_fence
        {
            return Err(StoreError::FenceMismatch);
        }
        let operation_id = transition.identity.operation_id.clone();
        let idempotency_key = transition.identity.idempotency_key.clone();
        let result = self
            .execute_raw(
                StoreRequest::Apply {
                    context: ctx.clone(),
                    transition,
                    expected_revision_heads,
                    expected_ordering_heads,
                },
                Some(ctx),
                &idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Transaction { receipt }) if receipt.operation_id == operation_id => {
                Ok(receipt)
            }
            // Once Apply has crossed the transport boundary, a valid response
            // with the wrong operation identity or response kind is itself an
            // uncertain observation. Reconcile only the operation that this
            // Kernel call admitted; never adopt an identity from the peer.
            Ok(_) => self.receipt_exact(operation_id).await,
            Err(RequestFailure::Unknown {
                operation_id: observed,
                ..
            }) => {
                // The peer's identity is evidence of a mismatch only; the
                // receipt lookup remains bound to our admitted operation.
                let _ = observed;
                self.receipt_exact(operation_id).await
            }
            Err(error) => Err(error.into_store_error()),
        }
    }

    async fn recovery(
        &self,
        request: StoreRecoveryRequest,
    ) -> Result<StoreRecoverySnapshot, StoreError> {
        request.validate()?;
        self.validate_requirement_fence(&request.state_fence)?;
        let response = self
            .execute_raw(
                StoreRequest::Recovery {
                    request: request.clone(),
                },
                None,
                "store-recovery",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        let StoreResponse::Recovery { snapshot } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        self.validate_recovery_snapshot(&request, &snapshot)?;
        Ok(snapshot)
    }

    async fn initialize_genesis(
        &self,
        context: &RequestMeta,
        request: StoreGenesisRequest,
    ) -> Result<WriteReceipt, StoreError> {
        request.validate_for_context(context)?;
        self.validate_requirement_fence(&context.state_fence)?;
        self.validate_requirement_fence(&request.state_fence)?;
        let operation_id = request.operation_id.clone();
        let result = self
            .execute_raw(
                StoreRequest::InitializeGenesis {
                    context: context.clone(),
                    request: request.clone(),
                },
                Some(context),
                &request.idempotency_key,
            )
            .await;
        match result {
            Ok(StoreResponse::Genesis { receipt }) if receipt.operation_id == operation_id => {
                self.validate_genesis_receipt(context, &request, &receipt)?;
                Ok(receipt)
            }
            Ok(_) | Err(RequestFailure::Unknown { .. }) => {
                self.reconcile_genesis(context, &request).await
            }
            Err(error) => Err(error.into_store_error()),
        }
    }

    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        let response = self
            .execute_raw(
                StoreRequest::Receipt {
                    operation_id: operation_id.clone(),
                },
                None,
                "store-receipt",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::Receipt {
                receipt: Some(receipt),
            } if receipt.operation_id == operation_id => Ok(Some(receipt)),
            StoreResponse::Receipt { receipt: None } => Ok(None),
            StoreResponse::Receipt { .. } => Err(StoreError::IdentityConflict),
            _ => Err(StoreError::InvalidReceipt),
        }
    }

    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        let response = self
            .execute_raw(
                StoreRequest::RevisionHeads { keys },
                None,
                "store-revision-heads",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::RevisionHeads { heads } => Ok(heads),
            _ => Err(StoreError::InvalidReceipt),
        }
    }

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        let response = self
            .execute_raw(
                StoreRequest::ValidationSnapshot,
                None,
                "store-validation-snapshot",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        let StoreResponse::ValidationSnapshot { snapshot } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        snapshot.validate()?;
        if snapshot.state_fence != self.requirement.state_fence
            || snapshot.state_fence.resource_generation != self.requirement.store_generation
            || snapshot.state_fence.authority_epoch != self.requirement.authority_epoch()
        {
            return Err(StoreError::FenceMismatch);
        }
        let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
        if snapshot.observed_at_unix_ms > now
            || now.saturating_sub(snapshot.observed_at_unix_ms) > 30_000
        {
            return Err(StoreError::Unavailable);
        }
        Ok(snapshot)
    }

    async fn scope_revision_view(
        &self,
        scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        let request = NamedReadRequest {
            operation: NamedReadOperation::GetScopeRevisionView,
            scope_id: Some(scope_id.clone()),
            consistency: ReadConsistency::ExactFence,
            state_fence: self.requirement.state_fence.clone(),
            parameters: BTreeMap::default(),
        };
        let response = self
            .execute_raw(
                StoreRequest::Named { request },
                None,
                "store-scope-revision-view",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        let StoreResponse::Named { response } = response else {
            return Err(StoreError::InvalidReceipt);
        };
        if response.operation != NamedReadOperation::GetScopeRevisionView
            || response.state_fence != self.requirement.state_fence
        {
            return Err(StoreError::FenceMismatch);
        }
        let view: ScopeRevisionView = serde_json::from_value(response.payload)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        view.validate()?;
        if view.scope_id != scope_id {
            return Err(StoreError::IdentityConflict);
        }
        Ok(view)
    }

    async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        let response = self
            .execute_raw(
                StoreRequest::OrderingHeads { scopes },
                None,
                "store-ordering-heads",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::OrderingHeads { heads } => Ok(heads),
            _ => Err(StoreError::InvalidReceipt),
        }
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        query.validate()?;
        if query.state_fence != self.requirement.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        let response = self
            .execute_raw(
                StoreRequest::Named { request: query },
                None,
                "store-named-read",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::Named { response } => Ok(response),
            _ => Err(StoreError::InvalidReceipt),
        }
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        let response = self
            .execute_raw(StoreRequest::Health, None, "store-health")
            .await
            .map_err(RequestFailure::into_store_error)?;
        match response {
            StoreResponse::Health { record } => Ok(record),
            _ => Err(StoreError::InvalidReceipt),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_wrap,
    clippy::expect_used,
    clippy::items_after_test_module,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use eliot_contracts::{
        AuthorityEpoch, ClockReading, ProductId, RequestId, ResourceGeneration, SourceId,
        StateFence,
    };
    use eliot_ipc::DeliveryOutcome;
    use eliot_platform::PlatformHandle;
    use eliot_protocol::{FrameKind, MessageType, ProtocolPayload, ServerHello};
    use eliot_store_api::StoreResponse;
    use serde_json::json;

    #[derive(Clone, Copy, Debug)]
    enum SnapshotFault {
        Valid,
        Unavailable,
        WrongRequestId,
        WrongFence,
        WrongGeneration,
        WrongAuthority,
        FutureTimestamp,
        StaleTimestamp,
        MalformedZeroRevision,
        DuplicateHeads,
        MixedHeadFence,
        SubstitutedConnection,
    }

    struct FakeEbpStoreTransport {
        requirement: HostStoreBootstrapRequirement,
        pending: Option<Frame>,
        fault: SnapshotFault,
        validation_calls: usize,
        recovery_response: Option<Box<StoreResponse>>,
        genesis_response: Option<Box<StoreResponse>>,
        reconciliation_receipt: Option<Box<WriteReceipt>>,
        recovery_calls: usize,
        genesis_calls: usize,
        receipt_requests: Vec<OperationId>,
    }

    impl FakeEbpStoreTransport {
        fn new(requirement: HostStoreBootstrapRequirement, fault: SnapshotFault) -> Self {
            Self {
                requirement,
                pending: None,
                fault,
                validation_calls: 0,
                recovery_response: None,
                genesis_response: None,
                reconciliation_receipt: None,
                recovery_calls: 0,
                genesis_calls: 0,
                receipt_requests: Vec::new(),
            }
        }

        fn with_recovery_response(mut self, response: StoreResponse) -> Self {
            self.recovery_response = Some(Box::new(response));
            self
        }

        fn with_genesis_response(mut self, response: StoreResponse) -> Self {
            self.genesis_response = Some(Box::new(response));
            self
        }

        fn with_reconciliation_receipt(mut self, receipt: WriteReceipt) -> Self {
            self.reconciliation_receipt = Some(Box::new(receipt));
            self
        }

        fn response(
            connection_id: String,
            request_id: RequestId,
            response: StoreResponse,
        ) -> Frame {
            eliot_store_api::response_frame(
                connection_id,
                ProtocolVersion::CURRENT,
                Some(request_id),
                response,
            )
            .expect("fake response")
        }

        fn raw_snapshot(
            connection_id: String,
            request_id: RequestId,
            value: serde_json::Value,
        ) -> Frame {
            Frame {
                protocol_version: ProtocolVersion::CURRENT,
                encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
                connection_id,
                request_id: Some(request_id),
                kind: FrameKind::Response,
                message_type: MessageType::Result,
                request_identity: None,
                payload: ProtocolPayload::Json(value),
                trace_context: BTreeMap::new(),
            }
        }
    }

    impl EbpStoreTransport for FakeEbpStoreTransport {
        fn ensure_authenticated(
            &self,
            _requirement: &HostStoreBootstrapRequirement,
        ) -> Result<(), StoreClientError> {
            Ok(())
        }

        async fn send_frame(
            &mut self,
            frame: &Frame,
            _limits: TransportLimits,
        ) -> Result<DeliveryOutcome, StoreClientError> {
            if frame.kind == FrameKind::Control {
                let hello = ServerHello {
                    selected_protocol: ProtocolVersion::CURRENT,
                    session_principal_binding: "fake-store-session".to_owned(),
                    allowed_capabilities: CAPABILITIES
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                    allowed_effects: EFFECTS.iter().map(|value| (*value).to_owned()).collect(),
                    config_snapshot: json!({
                        "config_hash": self.requirement.approved_config_hash.as_str(),
                        "artifact_hash": self.requirement.approved_artifact_hash.as_str(),
                    }),
                    heartbeat_ms: 1_000,
                    control_channel: "fake-store-control".to_owned(),
                    rejection_reason: None,
                    authority_epoch: self.requirement.authority_epoch(),
                };
                self.pending = Some(
                    eliot_ipc::server_hello_frame(self.requirement.connection_id.as_str(), &hello)
                        .expect("fake server hello"),
                );
                return Ok(DeliveryOutcome::Delivered);
            }
            let (request_id, _identity, request) =
                eliot_store_api::decode_request_frame(frame).map_err(StoreClientError::from)?;
            match request {
                StoreRequest::Readiness => {
                    self.pending = Some(Self::response(
                        self.requirement.connection_id.as_str().to_owned(),
                        request_id,
                        StoreResponse::Readiness {
                            receipt: eliot_store_api::ReadinessReceipt::ready("1.0.0".to_owned()),
                        },
                    ));
                }
                StoreRequest::ValidationSnapshot => {
                    self.validation_calls += 1;
                    let response_id = match self.fault {
                        SnapshotFault::WrongRequestId => {
                            RequestId::new("wrong-request").expect("id")
                        }
                        _ => request_id.clone(),
                    };
                    let connection_id = match self.fault {
                        SnapshotFault::SubstitutedConnection => "substituted-connection".to_owned(),
                        _ => self.requirement.connection_id.as_str().to_owned(),
                    };
                    let fence = match self.fault {
                        SnapshotFault::WrongFence | SnapshotFault::WrongAuthority => {
                            StateFence::new(
                                AuthorityEpoch::new(2).expect("epoch"),
                                ResourceGeneration::new(1).expect("generation"),
                            )
                        }
                        SnapshotFault::WrongGeneration => StateFence::new(
                            AuthorityEpoch::new(1).expect("epoch"),
                            ResourceGeneration::new(2).expect("generation"),
                        ),
                        _ => self.requirement.state_fence.clone(),
                    };
                    let observed_at_unix_ms = match self.fault {
                        SnapshotFault::FutureTimestamp => unix_ms().saturating_add(60_000) as i64,
                        SnapshotFault::StaleTimestamp => unix_ms().saturating_sub(60_000) as i64,
                        _ => unix_ms() as i64,
                    };
                    if matches!(self.fault, SnapshotFault::Unavailable) {
                        self.pending = Some(Self::response(
                            connection_id,
                            response_id,
                            StoreResponse::Error {
                                error: "unavailable".to_owned(),
                            },
                        ));
                    } else {
                        let head = json!({
                            "key": "scope:one",
                            "revision": 1,
                            "state_fence": fence,
                        });
                        let heads = match self.fault {
                            SnapshotFault::MalformedZeroRevision => json!([{
                                "key": "scope:one",
                                "revision": 0,
                                "state_fence": self.requirement.state_fence,
                            }]),
                            SnapshotFault::DuplicateHeads => json!([head.clone(), head]),
                            SnapshotFault::MixedHeadFence => json!([
                                head,
                                {
                                    "key": "scope:two",
                                    "revision": 1,
                                    "state_fence": StateFence::new(
                                        AuthorityEpoch::new(1).expect("epoch"),
                                        ResourceGeneration::new(2).expect("generation"),
                                    ),
                                }
                            ]),
                            _ => json!([]),
                        };
                        let snapshot = json!({
                            "state_fence": fence,
                            "revision_heads": heads,
                            "validation_revision": 1,
                            "observed_at_unix_ms": observed_at_unix_ms,
                        });
                        self.pending = Some(Self::raw_snapshot(
                            connection_id,
                            response_id,
                            json!({ "status": "validation_snapshot", "snapshot": snapshot }),
                        ));
                    }
                }
                StoreRequest::Recovery { .. } => {
                    self.recovery_calls += 1;
                    let response = *self.recovery_response.take().ok_or_else(|| {
                        StoreClientError::Contract("fake recovery response missing".to_owned())
                    })?;
                    self.pending = Some(Self::response(
                        self.requirement.connection_id.as_str().to_owned(),
                        request_id,
                        response,
                    ));
                }
                StoreRequest::InitializeGenesis { .. } => {
                    self.genesis_calls += 1;
                    let response = *self.genesis_response.take().ok_or_else(|| {
                        StoreClientError::Contract("fake genesis response missing".to_owned())
                    })?;
                    self.pending = Some(Self::response(
                        self.requirement.connection_id.as_str().to_owned(),
                        request_id,
                        response,
                    ));
                }
                StoreRequest::Receipt { operation_id } => {
                    self.receipt_requests.push(operation_id);
                    self.pending = Some(Self::response(
                        self.requirement.connection_id.as_str().to_owned(),
                        request_id,
                        StoreResponse::Receipt {
                            receipt: self.reconciliation_receipt.as_deref().cloned(),
                        },
                    ));
                }
                _ => {
                    return Err(StoreClientError::Contract(
                        "fake transport received unexpected request".to_owned(),
                    ));
                }
            }
            Ok(DeliveryOutcome::Delivered)
        }

        async fn receive_frame(
            &mut self,
            _limits: TransportLimits,
        ) -> Result<Frame, StoreClientError> {
            self.pending
                .take()
                .ok_or_else(|| StoreClientError::Transport("fake response missing".to_owned()))
        }
    }

    fn requirement() -> HostStoreBootstrapRequirement {
        let fence = StateFence::new(
            AuthorityEpoch::new(1).expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        );
        HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new("store_bridge").expect("route"),
            canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store").expect("pipe"),
            store_generation: ResourceGeneration::new(1).expect("generation"),
            state_fence: fence,
            launch_nonce: PlatformHandle::new("launch").expect("launch"),
            connection_id: PlatformHandle::new("connection").expect("connection"),
            expected_peer_sid: PlatformHandle::new("S-1-5-18").expect("sid"),
            expected_peer_session_id: 1,
            approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact"),
            approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config"),
            timeout_ms: 30_000,
        }
    }

    fn context_for(fence: &StateFence, request_id: &str, source_id: &str) -> RequestMeta {
        RequestMeta {
            request_id: RequestId::new(request_id).expect("request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product").expect("product"),
            source_id: SourceId::new(source_id).expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        }
    }

    fn recovery_record(
        fence: &StateFence,
        namespace: &str,
        key: &str,
        payload: &[u8],
    ) -> eliot_store_api::RecoveryRecord {
        eliot_store_api::RecoveryRecord {
            namespace: namespace.to_owned(),
            key: key.to_owned(),
            state_fence: fence.clone(),
            revision: 1,
            schema: eliot_store_api::OWNER_SNAPSHOT_SCHEMA.to_owned(),
            payload: payload.to_vec(),
            value_digest: eliot_store_api::sha256_hex(payload),
        }
    }

    fn recovery_request(
        fence: &StateFence,
        records: Vec<RecoveryRecordKey>,
        include_receipts: bool,
        include_jobs: bool,
    ) -> StoreRecoveryRequest {
        StoreRecoveryRequest {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            state_fence: fence.clone(),
            records,
            include_receipts,
            include_jobs,
        }
    }

    fn recovery_snapshot(
        fence: &StateFence,
        owner_records: Vec<eliot_store_api::RecoveryRecord>,
        job_records: Vec<eliot_store_api::RecoveryRecord>,
        receipts: Vec<WriteReceipt>,
    ) -> StoreRecoverySnapshot {
        let snapshot = StoreRecoverySnapshot {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            state_fence: fence.clone(),
            validation_revision: 1,
            canonical_scope: ScopeRevisionView {
                scope_id: ScopeId::new("store").expect("scope"),
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
                state_fence: fence.clone(),
            },
            owner_records,
            job_records,
            receipts,
        };
        snapshot.validate().expect("recovery snapshot");
        snapshot
    }

    fn genesis_request(
        fence: &StateFence,
        operation_id: &str,
        idempotency_key: &str,
    ) -> StoreGenesisRequest {
        StoreGenesisRequest {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            operation_id: OperationId::new(operation_id).expect("operation id"),
            idempotency_key: idempotency_key.to_owned(),
            canonical_request_hash: String::new(),
            state_fence: fence.clone(),
            owner_records: vec![recovery_record(
                fence,
                "owner",
                "current",
                br#"{"current_plan":null}"#,
            )],
        }
        .with_computed_digest()
        .expect("genesis request")
    }

    fn genesis_receipt(context: &RequestMeta, request: &StoreGenesisRequest) -> WriteReceipt {
        let transition =
            eliot_store_api::genesis_transition(context, request).expect("genesis transition");
        let mut receipt = WriteReceipt {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            canonical_request_hash: request.canonical_request_hash.clone(),
            transition_class: eliot_store_api::TransitionClass::RecoverySchema,
            status: eliot_store_api::WriteReceiptStatus::Committed,
            commit_id: Some(eliot_store_api::CommitId::new("commit-genesis").expect("commit")),
            state_fence: request.state_fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["genesis-seed".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            error_code: None,
            resubmission: eliot_store_api::Resubmission::None,
            committed_at: Some(format!("commit-sequence-{0:016}", 1)),
            envelope: None,
        };
        assert_eq!(context.state_fence, transition.state_fence);
        assert_eq!(context.state_fence, receipt.state_fence);
        assert_eq!(receipt.operation_id, transition.identity.operation_id);
        assert_eq!(receipt.idempotency_key, transition.identity.idempotency_key);
        assert_eq!(
            receipt.canonical_request_hash,
            transition.identity.canonical_request_hash
        );
        assert_eq!(receipt.transition_class, transition.transition_class);
        assert_eq!(
            receipt.operation_manifest_digest,
            transition.operation_manifest_digest
        );
        assert_eq!(
            receipt.status,
            eliot_store_api::WriteReceiptStatus::Committed
        );
        assert!(receipt.commit_id.is_some());
        receipt.envelope = Some(
            eliot_store_api::issue_genesis_receipt_envelope(context, request, &receipt, 1)
                .expect("genesis envelope"),
        );
        receipt.validate().expect("genesis receipt");
        receipt
    }

    #[tokio::test]
    async fn recovery_client_accepts_exact_snapshot_and_enforces_request_ceilings() {
        let requirement = requirement();
        let fence = requirement.state_fence.clone();
        let owner = recovery_record(&fence, "owner", "current", b"owner-state");
        let request = recovery_request(&fence, vec![owner.record_key()], false, false);
        let snapshot = recovery_snapshot(&fence, vec![owner], Vec::new(), Vec::new());
        let transport = FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
            .with_recovery_response(StoreResponse::Recovery { snapshot });
        let client = EbpCanonicalStoreClient::connect(transport, requirement)
            .await
            .expect("fake handshake and readiness");

        let recovered = client.recovery(request).await.expect("recovery snapshot");
        assert_eq!(recovered.owner_records.len(), 1);
        assert!(recovered.job_records.is_empty());
        assert!(recovered.receipts.is_empty());
        let transport = client.transport.lock().await;
        assert_eq!(transport.recovery_calls, 1);
    }

    #[tokio::test]
    async fn recovery_client_rejects_wrong_fence_key_and_excluded_jobs() {
        let approved_requirement = requirement();
        let wrong_fence = StateFence::new(
            AuthorityEpoch::new(2).expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        );
        let owner = recovery_record(
            &approved_requirement.state_fence,
            "owner",
            "current",
            b"owner-state",
        );
        let wrong_fence_request =
            recovery_request(&wrong_fence, vec![owner.record_key()], false, false);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(approved_requirement.clone(), SnapshotFault::Valid),
            approved_requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        assert_eq!(
            client.recovery(wrong_fence_request).await,
            Err(StoreError::FenceMismatch)
        );
        assert_eq!(client.transport.lock().await.recovery_calls, 0);

        let requirement = requirement();
        let fence = requirement.state_fence.clone();
        let requested_owner = recovery_record(&fence, "owner", "current", b"owner-state");
        let substituted_owner = recovery_record(&fence, "owner", "substituted", b"owner-state");
        let request = recovery_request(&fence, vec![requested_owner.record_key()], false, false);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_recovery_response(StoreResponse::Recovery {
                    snapshot: recovery_snapshot(
                        &fence,
                        vec![substituted_owner],
                        Vec::new(),
                        Vec::new(),
                    ),
                }),
            requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        assert!(client.recovery(request.clone()).await.is_err());

        let job = recovery_record(&fence, "job", "one", b"job-state");
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_recovery_response(StoreResponse::Recovery {
                    snapshot: recovery_snapshot(
                        &fence,
                        vec![requested_owner],
                        vec![job],
                        Vec::new(),
                    ),
                }),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");
        assert!(client.recovery(request).await.is_err());
    }

    #[tokio::test]
    async fn genesis_client_accepts_direct_store_receipt() {
        let requirement = requirement();
        let context = context_for(&requirement.state_fence, "genesis-request", "source");
        let request = genesis_request(&requirement.state_fence, "genesis-1", "genesis-retry-1");
        let receipt = genesis_receipt(&context, &request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Genesis {
                    receipt: receipt.clone(),
                }),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");

        assert_eq!(
            client
                .initialize_genesis(&context, request)
                .await
                .expect("genesis receipt"),
            receipt
        );
        let transport = client.transport.lock().await;
        assert_eq!(transport.genesis_calls, 1);
        assert!(transport.receipt_requests.is_empty());
    }

    #[tokio::test]
    async fn genesis_client_reconciles_unknown_and_wrong_response_by_admitted_operation() {
        let first_requirement = requirement();
        let context = context_for(&first_requirement.state_fence, "genesis-request", "source");
        let request = genesis_request(
            &first_requirement.state_fence,
            "genesis-1",
            "genesis-retry-1",
        );
        let receipt = genesis_receipt(&context, &request);
        let peer_operation = OperationId::new("peer-operation").expect("peer operation");
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(first_requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Unknown {
                    operation_id: peer_operation,
                    reason: "peer uncertainty".to_owned(),
                })
                .with_reconciliation_receipt(receipt.clone()),
            first_requirement,
        )
        .await
        .expect("fake handshake and readiness");
        assert_eq!(
            client
                .initialize_genesis(&context, request.clone())
                .await
                .expect("reconciled receipt"),
            receipt
        );
        assert_eq!(
            client.transport.lock().await.receipt_requests,
            vec![request.operation_id.clone()]
        );

        let requirement = requirement();
        let context = context_for(&requirement.state_fence, "genesis-request", "source");
        let request = genesis_request(&requirement.state_fence, "genesis-1", "genesis-retry-1");
        let receipt = genesis_receipt(&context, &request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Transaction {
                    receipt: receipt.clone(),
                })
                .with_reconciliation_receipt(receipt),
            requirement,
        )
        .await
        .expect("fake handshake and readiness");
        assert!(client.initialize_genesis(&context, request).await.is_ok());
        assert_eq!(client.transport.lock().await.receipt_requests.len(), 1);
    }

    #[tokio::test]
    async fn genesis_client_rejects_substituted_operation_idempotency_and_envelope() {
        let approved_requirement = requirement();
        let context = context_for(
            &approved_requirement.state_fence,
            "genesis-request",
            "source",
        );
        let request = genesis_request(
            &approved_requirement.state_fence,
            "genesis-1",
            "genesis-retry-1",
        );
        let peer_request = genesis_request(
            &approved_requirement.state_fence,
            "peer-operation",
            "peer-idem",
        );
        let peer_receipt = genesis_receipt(&context, &peer_request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(approved_requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Genesis {
                    receipt: peer_receipt.clone(),
                })
                .with_reconciliation_receipt(peer_receipt),
            approved_requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        assert!(
            client
                .initialize_genesis(&context, request.clone())
                .await
                .is_err()
        );
        assert_eq!(
            client.transport.lock().await.receipt_requests,
            vec![request.operation_id.clone()]
        );

        let substituted_request = genesis_request(
            &approved_requirement.state_fence,
            request.operation_id.as_str(),
            "substituted-idem",
        );
        let substituted_receipt = genesis_receipt(&context, &substituted_request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(approved_requirement.clone(), SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Genesis {
                    receipt: substituted_receipt,
                }),
            approved_requirement.clone(),
        )
        .await
        .expect("fake handshake and readiness");
        assert!(
            client
                .initialize_genesis(&context, request.clone())
                .await
                .is_err()
        );
        assert!(client.transport.lock().await.receipt_requests.is_empty());

        let substituted_context = context_for(
            &approved_requirement.state_fence,
            "substituted-request",
            "other-source",
        );
        let substituted_receipt = genesis_receipt(&substituted_context, &request);
        let client = EbpCanonicalStoreClient::connect(
            FakeEbpStoreTransport::new(approved_requirement, SnapshotFault::Valid)
                .with_genesis_response(StoreResponse::Genesis {
                    receipt: substituted_receipt,
                }),
            requirement(),
        )
        .await
        .expect("fake handshake and readiness");
        assert!(client.initialize_genesis(&context, request).await.is_err());
        assert!(client.transport.lock().await.receipt_requests.is_empty());
    }

    #[tokio::test]
    async fn validation_snapshot_transport_matrix_is_one_call_and_fail_closed() {
        let faults = [
            SnapshotFault::Unavailable,
            SnapshotFault::WrongRequestId,
            SnapshotFault::WrongFence,
            SnapshotFault::WrongGeneration,
            SnapshotFault::WrongAuthority,
            SnapshotFault::FutureTimestamp,
            SnapshotFault::StaleTimestamp,
            SnapshotFault::MalformedZeroRevision,
            SnapshotFault::DuplicateHeads,
            SnapshotFault::MixedHeadFence,
            SnapshotFault::SubstitutedConnection,
        ];
        for fault in faults {
            let req = requirement();
            let transport = FakeEbpStoreTransport::new(req.clone(), fault);
            let client = EbpCanonicalStoreClient::connect(transport, req)
                .await
                .expect("fake handshake and readiness");
            assert!(
                client.validation_snapshot().await.is_err(),
                "fault {fault:?} unexpectedly produced a valid snapshot"
            );
            let transport = client.transport.lock().await;
            assert_eq!(transport.validation_calls, 1);
        }
        let req = requirement();
        let transport = FakeEbpStoreTransport::new(req.clone(), SnapshotFault::Valid);
        let client = EbpCanonicalStoreClient::connect(transport, req)
            .await
            .expect("positive fake handshake and readiness");
        let snapshot = client
            .validation_snapshot()
            .await
            .expect("empty canonical snapshot");
        assert!(snapshot.revision_heads.is_empty());
        let transport = client.transport.lock().await;
        assert_eq!(transport.validation_calls, 1);
    }
}

fn client_hello(
    requirement: &HostStoreBootstrapRequirement,
) -> Result<ClientHello, StoreClientError> {
    let module_id = ContractId::new(STORE_MODULE_IDENTITY)
        .map_err(|error| StoreClientError::Contract(error.to_string()))?;
    let artifact_id = ArtifactId::new(requirement.approved_artifact_hash.as_str())
        .map_err(|error| StoreClientError::Contract(error.to_string()))?;
    let module_contract = ModuleContract {
        module_id: module_id.clone(),
        version: ContractVersion::new(1, 0, 0),
        artifact_id: artifact_id.clone(),
        protocols: vec!["eliot.s03.ebp.v1".to_owned()],
        required_capabilities: vec![
            "store.readiness".to_owned(),
            "store.apply".to_owned(),
            "store.validation_snapshot".to_owned(),
        ],
        optional_capabilities: Vec::new(),
        advisory_capabilities: Vec::new(),
        state_owner: "eliot-kernel".to_owned(),
        failure_domain: "canonical-store".to_owned(),
        hot_replace: false,
    };
    Ok(ClientHello {
        protocol_range: ProtocolRange {
            minimum: ProtocolVersion::CURRENT,
            maximum: ProtocolVersion::CURRENT,
        },
        module_bridge_identity: module_id.as_str().to_owned(),
        artifact_hash: artifact_id.clone(),
        module_contract,
        module_generation: ModuleGeneration {
            module_id,
            generation: requirement.store_generation,
            artifact_id,
            state: ModuleGenerationState::Active,
            health: eliot_runtime_contracts::HealthVector::healthy(),
            state_fence: requirement.state_fence.clone(),
        },
        launch_nonce: requirement.launch_nonce.as_str().to_owned(),
        capabilities: CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        privacy_classes: vec!["PUBLIC".to_owned()],
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
            .map_err(|_| StoreClientError::Contract("protocol max frame exceeds u32".to_owned()))?,
        authority_epoch: requirement.authority_epoch(),
    })
}

fn decode_server_hello(
    frame: &Frame,
    requirement: &HostStoreBootstrapRequirement,
) -> Result<ServerHello, StoreClientError> {
    let server = eliot_ipc::decode_server_hello_frame(frame, requirement.connection_id.as_str())?;
    let config_hash = server
        .config_snapshot
        .get("config_hash")
        .and_then(serde_json::Value::as_str);
    let artifact_hash = server
        .config_snapshot
        .get("artifact_hash")
        .and_then(serde_json::Value::as_str);
    let expected_capabilities: BTreeSet<&str> = CAPABILITIES.iter().copied().collect();
    let observed_capabilities: BTreeSet<&str> = server
        .allowed_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    let expected_effects: BTreeSet<&str> = EFFECTS.iter().copied().collect();
    let observed_effects: BTreeSet<&str> =
        server.allowed_effects.iter().map(String::as_str).collect();
    if server.authority_epoch != requirement.authority_epoch()
        || server.selected_protocol != ProtocolVersion::CURRENT
        || server.rejection_reason.is_some()
        || artifact_hash != Some(requirement.approved_artifact_hash.as_str())
        || config_hash != Some(requirement.approved_config_hash.as_str())
        || observed_capabilities != expected_capabilities
        || observed_effects != expected_effects
    {
        return Err(StoreClientError::Contract(
            "store handshake did not admit the exact authority/fence capability set".to_owned(),
        ));
    }
    Ok(server)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(windows)]
impl EbpStoreTransport for eliot_ipc::NamedPipeTransport {
    fn ensure_authenticated(
        &self,
        requirement: &HostStoreBootstrapRequirement,
    ) -> Result<(), StoreClientError> {
        let identity = self.peer_identity();
        identity.validate().map_err(StoreClientError::from)?;
        match identity {
            eliot_ipc::PeerIdentity::Authenticated {
                user_identity,
                session_identity,
                ..
            } if user_identity == requirement.expected_peer_sid.as_str()
                && session_identity == &requirement.expected_peer_session_id.to_string() =>
            {
                Ok(())
            }
            _ => Err(StoreClientError::Transport(
                "authenticated store peer does not match Host-approved SID/session".to_owned(),
            )),
        }
    }

    async fn send_frame(
        &mut self,
        frame: &Frame,
        limits: TransportLimits,
    ) -> Result<DeliveryOutcome, StoreClientError> {
        eliot_ipc::NamedPipeTransport::send_frame(self, frame, limits)
            .await
            .map_err(Into::into)
    }

    async fn receive_frame(&mut self, limits: TransportLimits) -> Result<Frame, StoreClientError> {
        eliot_ipc::NamedPipeTransport::receive_frame(self, limits)
            .await
            .map_err(Into::into)
    }
}
