//! Kernel-owned, store-neutral S-03 EBP client.
//!
//! The client owns only authenticated EBP framing and closed store-api
//! operations.  It never opens a provider SDK, constructs a query, mints
//! authority, or decides completion.  An uncertain apply is reconciled only
//! by the exact operation identity carried by the prepared transition.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{ArtifactId, ContractId, ContractVersion, ProductId, RequestId, SourceId};
use eliot_ipc::{DeliveryOutcome, TransportError, TransportLimits};
use eliot_protocol::{
    ClientHello, Frame, ProtocolRange, ProtocolVersion, RequestIdentity, ServerHello,
};
use eliot_receipts::RequestBinding;
use eliot_runtime_contracts::{ModuleContract, ModuleGeneration, ModuleGenerationState};
use eliot_store_api::{
    CAPABILITIES, CanonicalStoreClient, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    OperationId, OrderingHead, OrderingHeadExpectation, OrderingScopeId, PreparedTransition,
    ReadConsistency, RequestMeta, RevisionHead, RevisionHeadExpectation, RevisionKey, ScopeId,
    ScopeRevisionView, StoreError, StoreHealth, StoreRequest, StoreResponse, StoreWireError,
    WriteReceipt,
};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::HostStoreBootstrapRequirement;

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
            .field("schema_generation", &self.requirement.schema_generation)
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
            || receipt.expected_generation.as_deref()
                != Some(self.requirement.schema_generation.as_str())
            || receipt.observed_generation.as_deref()
                != Some(self.requirement.schema_generation.as_str())
        {
            return Err(StoreClientError::Contract(
                "store schema generation is not the Host-approved ready generation".to_owned(),
            ));
        }
        Ok(())
    }

    async fn execute_raw(
        &self,
        request: StoreRequest,
        context: Option<&RequestMeta>,
        idempotency_key: &str,
    ) -> Result<StoreResponse, RequestFailure> {
        let request_id = context
            .map(|value| value.request_id.clone())
            .unwrap_or_else(|| self.next_request_id(idempotency_key));
        let metadata = context
            .cloned()
            .unwrap_or_else(|| self.read_metadata(request_id.clone()));
        if metadata.state_fence != self.requirement.state_fence {
            return Err(RequestFailure::Store(StoreError::FenceMismatch));
        }
        let identity = RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: self.requirement.state_fence.clone(),
            },
            idempotency_key: idempotency_key.to_owned(),
            deadline_unix_ms: unix_ms().saturating_add(30_000),
            cancellation_id: format!("{}:cancel", request_id),
        };
        let operation_id = match &request {
            StoreRequest::Apply { transition, .. } => {
                Some(transition.identity.operation_id.clone())
            }
            StoreRequest::Receipt { operation_id } => Some(operation_id.clone()),
            _ => None,
        };
        let frame = eliot_store_api::request_frame(
            self.requirement.connection_id.as_str(),
            self.protocol_version,
            request_id.clone(),
            identity,
            request,
        )
        .map_err(|error| RequestFailure::Contract(error.into()))?;
        let mut transport = self.transport.lock().await;
        let outcome = transport
            .send_frame(&frame, self.limits)
            .await
            .map_err(|error| RequestFailure::unknown_or_transport(error, operation_id.clone()))?;
        if outcome == DeliveryOutcome::UnknownOutcome {
            return Err(RequestFailure::unknown_or_transport(
                StoreClientError::Transport("store apply delivery is unknown".to_owned()),
                operation_id.clone(),
            ));
        }
        let response_frame = transport
            .receive_frame(self.limits)
            .await
            .map_err(|error| RequestFailure::unknown_or_transport(error, operation_id.clone()))?;
        let (response_id, response) = eliot_store_api::decode_response_frame(&response_frame)
            .map_err(|error| match operation_id.clone() {
                Some(operation_id) => RequestFailure::Unknown {
                    operation_id,
                    reason: error.to_string(),
                },
                None => RequestFailure::Contract(error.into()),
            })?;
        if response_id != request_id {
            return Err(RequestFailure::Store(StoreError::IdentityConflict));
        }
        response
            .validate()
            .map_err(|error| RequestFailure::Contract(error.into()))?;
        match response {
            StoreResponse::Error { error } => {
                Err(RequestFailure::Store(StoreError::Serialization(error)))
            }
            StoreResponse::Unknown {
                operation_id,
                reason,
            } => Err(RequestFailure::Unknown {
                operation_id,
                reason,
            }),
            response => Ok(response),
        }
    }

    async fn receipt_exact(&self, operation_id: OperationId) -> Result<WriteReceipt, StoreError> {
        let expected = operation_id.clone();
        let response = self
            .execute_raw(
                StoreRequest::Receipt { operation_id },
                None,
                "store-reconcile-receipt",
            )
            .await
            .map_err(RequestFailure::into_store_error)?;
        let StoreResponse::Receipt {
            receipt: Some(receipt),
        } = response
        else {
            return Err(StoreError::Unavailable);
        };
        if receipt.operation_id != expected {
            return Err(StoreError::IdentityConflict);
        }
        Ok(receipt)
    }

    fn next_request_id(&self, operation: &str) -> RequestId {
        let counter = self.request_counter.fetch_add(1, Ordering::Relaxed);
        RequestId::new(format!(
            "{}:{}:{}",
            self.requirement.connection_id.as_str(),
            operation,
            counter
        ))
        .expect("request identity is constructed from validated bootstrap data")
    }

    fn read_metadata(&self, request_id: RequestId) -> RequestMeta {
        RequestMeta {
            request_id,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("eliot-kernel").expect("static product id"),
            source_id: SourceId::new("eliot-kernel-store-client").expect("static source id"),
            state_fence: self.requirement.state_fence.clone(),
            clock: Default::default(),
        }
    }
}

#[derive(Debug)]
enum RequestFailure {
    Store(StoreError),
    Contract(StoreClientError),
    Unknown {
        operation_id: OperationId,
        reason: String,
    },
}

impl RequestFailure {
    fn unknown_or_transport(error: StoreClientError, operation_id: Option<OperationId>) -> Self {
        match operation_id {
            Some(operation_id) => Self::Unknown {
                operation_id,
                reason: error.to_string(),
            },
            None => Self::Contract(error),
        }
    }

    fn into_store_error(self) -> StoreError {
        match self {
            Self::Store(error) => error,
            Self::Contract(error) => StoreError::Serialization(error.to_string()),
            // Apply paths handle `Unknown` before reaching this conversion and
            // reconcile by the exact operation id. A standalone readback that
            // is itself unknown is only an unavailable observation.
            Self::Unknown { reason, .. } => {
                let _ = reason;
                StoreError::Unavailable
            }
        }
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
            Ok(StoreResponse::Transaction { .. }) => Err(StoreError::IdentityConflict),
            Ok(_) => Err(StoreError::InvalidReceipt),
            Err(RequestFailure::Unknown {
                operation_id: observed,
                reason: _,
            }) if observed == operation_id => self.receipt_exact(operation_id).await,
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

    async fn scope_revision_view(
        &self,
        scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        let request = NamedReadRequest {
            operation: NamedReadOperation::GetScopeRevisionView,
            scope_id: Some(scope_id.clone()),
            consistency: ReadConsistency::ExactFence,
            state_fence: self.requirement.state_fence.clone(),
            parameters: Default::default(),
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

fn client_hello(
    requirement: &HostStoreBootstrapRequirement,
) -> Result<ClientHello, StoreClientError> {
    let module_id = ContractId::new("eliot-store-surreal")
        .map_err(|error| StoreClientError::Contract(error.to_string()))?;
    let artifact_id = ArtifactId::new(requirement.approved_artifact_hash.as_str())
        .map_err(|error| StoreClientError::Contract(error.to_string()))?;
    let module_contract = ModuleContract {
        module_id: module_id.clone(),
        version: ContractVersion::new(1, 0, 0),
        artifact_id: artifact_id.clone(),
        protocols: vec!["eliot.s03.ebp.v1".to_owned()],
        required_capabilities: vec!["store.readiness".to_owned(), "store.apply".to_owned()],
        optional_capabilities: Vec::new(),
        advisory_capabilities: Vec::new(),
        state_owner: "eliot-kernel".to_owned(),
        failure_domain: "eliot-store-surreal".to_owned(),
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
        max_frame: eliot_protocol::MAX_FRAME_BYTES as u32,
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
    if server.authority_epoch != requirement.authority_epoch()
        || artifact_hash != Some(requirement.approved_artifact_hash.as_str())
        || config_hash != Some(requirement.approved_config_hash.as_str())
        || !CAPABILITIES.iter().all(|capability| {
            server
                .allowed_capabilities
                .iter()
                .any(|value| value == capability)
        })
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

#[cfg(all(test, windows))]
mod windows_e2e_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, atomic::AtomicU64};
    use std::time::Duration;

    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
    use eliot_ipc::NamedPipeServer;
    use eliot_platform::PlatformHandle;
    use eliot_store_api::{
        EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationIdentity, OperationManifestDigest, ReadinessReceipt, SecurityContext,
        StoreResponse, TransitionClass,
    };
    use tokio::sync::Mutex;

    fn requirement(pipe: String) -> HostStoreBootstrapRequirement {
        let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .expect("current process expectation");
        HostStoreBootstrapRequirement {
            store_pipe: PlatformHandle::new(pipe).expect("pipe handle"),
            store_generation: ResourceGeneration::genesis(),
            schema_generation: PlatformHandle::new("1.0.0").expect("schema handle"),
            state_fence: fence,
            launch_nonce: PlatformHandle::new("launch-e2e").expect("launch nonce"),
            connection_id: PlatformHandle::new("connection-e2e").expect("connection id"),
            expected_peer_sid: PlatformHandle::new(expectation.expected_sid()).expect("peer sid"),
            expected_peer_session_id: expectation.expected_session_id(),
            approved_artifact_hash: PlatformHandle::new("a".repeat(64)).expect("artifact hash"),
            approved_config_hash: PlatformHandle::new("b".repeat(64)).expect("config hash"),
        }
    }

    fn prepared_transition(fence: StateFence) -> PreparedTransition {
        let mut parameters = BTreeMap::new();
        parameters.insert("subject".to_owned(), serde_json::json!("e2e"));
        PreparedTransition {
            identity: OperationIdentity {
                operation_id: OperationId::new("operation-e2e").expect("operation id"),
                idempotency_key: "idempotency-e2e".to_owned(),
                canonical_request_hash: "c".repeat(64),
            },
            state_fence: fence,
            scope_id: ScopeId::new("scope-e2e").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-e2e").expect("ordering scope")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: eliot_store_api::EffectClass::Candidate,
            admission_contract_set_digest: "d".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-e2e")
                .expect("manifest"),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters,
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_s03_unknown_response_reconciles_exact_operation() {
        let pipe = format!(
            r"\\.\pipe\eliot\s03-e2e\{}-{}",
            std::process::id(),
            unix_ms()
        );
        let requirement = requirement(pipe.clone());
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .expect("current process expectation");
        let mut server = NamedPipeServer::create(&pipe, &expectation).expect("secured pipe");
        let server_expectation = expectation.clone();
        let server_requirement = requirement.clone();
        let server_task = tokio::spawn(async move {
            server
                .wait_for_authenticated_client(Duration::from_secs(5), &server_expectation)
                .await
                .map_err(|error| error.to_string())?;
            let limits = TransportLimits::default();
            let hello = server
                .receive_frame(limits)
                .await
                .map_err(|error| error.to_string())?;
            let hello = eliot_ipc::decode_client_hello_frame(
                &hello,
                server_requirement.connection_id.as_str(),
            )
            .map_err(|error| error.to_string())?;
            assert_eq!(hello.launch_nonce, server_requirement.launch_nonce.as_str());
            assert_eq!(
                hello.artifact_hash.as_str(),
                server_requirement.approved_artifact_hash.as_str()
            );
            let server_hello = ServerHello {
                selected_protocol: ProtocolVersion::CURRENT,
                session_principal_binding: "s03-test-server".to_owned(),
                allowed_capabilities: CAPABILITIES
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                allowed_effects: vec!["read".to_owned(), "canonical_write".to_owned()],
                config_snapshot: serde_json::json!({
                    "artifact_hash": server_requirement.approved_artifact_hash.as_str(),
                    "config_hash": server_requirement.approved_config_hash.as_str(),
                }),
                heartbeat_ms: 30_000,
                control_channel: "named_pipe".to_owned(),
                rejection_reason: None,
                authority_epoch: server_requirement.authority_epoch(),
            };
            let frame = eliot_ipc::server_hello_frame(
                server_requirement.connection_id.as_str(),
                &server_hello,
            )
            .map_err(|error| error.to_string())?;
            server
                .send_frame(&frame, limits)
                .await
                .map_err(|error| error.to_string())?;

            let readiness = server
                .receive_frame(limits)
                .await
                .map_err(|error| error.to_string())?;
            let (request_id, _, request) = eliot_store_api::decode_request_frame(&readiness)
                .map_err(|error| error.to_string())?;
            assert!(matches!(request, StoreRequest::Readiness));
            let readiness = eliot_store_api::response_frame(
                server_requirement.connection_id.as_str(),
                ProtocolVersion::CURRENT,
                Some(request_id),
                StoreResponse::Readiness {
                    receipt: ReadinessReceipt::ready(
                        server_requirement.schema_generation.as_str().to_owned(),
                    ),
                },
            )
            .map_err(|error| error.to_string())?;
            server
                .send_frame(&readiness, limits)
                .await
                .map_err(|error| error.to_string())?;

            let apply = server
                .receive_frame(limits)
                .await
                .map_err(|error| error.to_string())?;
            let (request_id, _, request) =
                eliot_store_api::decode_request_frame(&apply).map_err(|error| error.to_string())?;
            let operation_id = match request {
                StoreRequest::Apply { transition, .. } => transition.identity.operation_id,
                other => panic!("expected apply, got {other:?}"),
            };
            let unknown = eliot_store_api::response_frame(
                server_requirement.connection_id.as_str(),
                ProtocolVersion::CURRENT,
                Some(request_id),
                StoreResponse::Unknown {
                    operation_id: operation_id.clone(),
                    reason: "test delivery boundary is unknown".to_owned(),
                },
            )
            .map_err(|error| error.to_string())?;
            server
                .send_frame(&unknown, limits)
                .await
                .map_err(|error| error.to_string())?;

            let receipt_request = server
                .receive_frame(limits)
                .await
                .map_err(|error| error.to_string())?;
            let (request_id, _, request) = eliot_store_api::decode_request_frame(&receipt_request)
                .map_err(|error| error.to_string())?;
            let requested_operation = match request {
                StoreRequest::Receipt { operation_id } => operation_id,
                other => panic!("expected receipt reconciliation, got {other:?}"),
            };
            assert_eq!(requested_operation, operation_id);
            let receipt = eliot_store_api::response_frame(
                server_requirement.connection_id.as_str(),
                ProtocolVersion::CURRENT,
                Some(request_id),
                StoreResponse::Receipt { receipt: None },
            )
            .map_err(|error| error.to_string())?;
            server
                .send_frame(&receipt, limits)
                .await
                .map_err(|error| error.to_string())?;
            Ok::<OperationId, String>(operation_id)
        });

        let transport = eliot_ipc::NamedPipeTransport::connect_authenticated(
            &pipe,
            Duration::from_secs(5),
            &expectation,
        )
        .await
        .expect("authenticated client transport");
        let client = EbpCanonicalStoreClient::connect(transport, requirement.clone())
            .await
            .expect("S03 client handshake");
        let context = client
            .read_metadata(eliot_contracts::RequestId::new("request-e2e").expect("request id"));
        let result = client
            .apply_prepared(
                &context,
                prepared_transition(requirement.state_fence),
                Vec::new(),
                Vec::new(),
            )
            .await;
        assert!(matches!(result, Err(StoreError::Unavailable)));
        let operation_id = server_task
            .await
            .expect("server task")
            .expect("server protocol");
        assert_eq!(operation_id.as_str(), "operation-e2e");
    }

    #[derive(Clone, Copy)]
    enum UnknownBoundary {
        Send,
        Receive,
    }

    struct FakeTransport {
        boundary: UnknownBoundary,
        applied: Option<OperationId>,
        reconciled: Option<OperationId>,
        last_request_id: Option<RequestId>,
        receive_failed: bool,
    }

    impl EbpStoreTransport for FakeTransport {
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
            let (request_id, _, request) = eliot_store_api::decode_request_frame(frame)
                .map_err(|error| StoreClientError::Contract(error.to_string()))?;
            self.last_request_id = Some(request_id);
            match request {
                StoreRequest::Apply { transition, .. } => {
                    self.applied = Some(transition.identity.operation_id);
                    if matches!(self.boundary, UnknownBoundary::Send) {
                        Ok(DeliveryOutcome::UnknownOutcome)
                    } else {
                        Ok(DeliveryOutcome::Delivered)
                    }
                }
                StoreRequest::Receipt { operation_id } => {
                    self.reconciled = Some(operation_id);
                    Ok(DeliveryOutcome::Delivered)
                }
                _ => Ok(DeliveryOutcome::Delivered),
            }
        }

        async fn receive_frame(
            &mut self,
            _limits: TransportLimits,
        ) -> Result<Frame, StoreClientError> {
            if matches!(self.boundary, UnknownBoundary::Receive) && !self.receive_failed {
                self.receive_failed = true;
                return Err(StoreClientError::Transport(
                    "test receive crossed an unknown boundary".to_owned(),
                ));
            }
            let request_id = self.last_request_id.clone().ok_or_else(|| {
                StoreClientError::Contract("receipt was not requested".to_owned())
            })?;
            eliot_store_api::response_frame(
                "connection-e2e",
                ProtocolVersion::CURRENT,
                Some(request_id),
                StoreResponse::Receipt { receipt: None },
            )
            .map_err(|error| StoreClientError::Contract(error.to_string()))
        }
    }

    async fn apply_with_fake_boundary(
        boundary: UnknownBoundary,
    ) -> (StoreError, Option<OperationId>) {
        let requirement = requirement(format!(
            r"\\.\pipe\eliot\s03-fake\{}-{}",
            std::process::id(),
            unix_ms()
        ));
        let transport = FakeTransport {
            boundary,
            applied: None,
            reconciled: None,
            last_request_id: None,
            receive_failed: false,
        };
        let transport_state = Arc::new(Mutex::new(transport));
        let client = EbpCanonicalStoreClient {
            transport: transport_state.clone(),
            requirement: requirement.clone(),
            protocol_version: ProtocolVersion::CURRENT,
            limits: TransportLimits::default(),
            request_counter: AtomicU64::new(1),
        };
        let context = client
            .read_metadata(eliot_contracts::RequestId::new("request-fake").expect("request id"));
        let result = client
            .apply_prepared(
                &context,
                prepared_transition(requirement.state_fence),
                Vec::new(),
                Vec::new(),
            )
            .await
            .expect_err("unknown boundary must not succeed");
        let transport = transport_state.lock().await;
        (result, transport.reconciled.clone())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_send_preserves_exact_operation_for_receipt_lookup() {
        let (error, reconciled) = apply_with_fake_boundary(UnknownBoundary::Send).await;
        assert!(matches!(error, StoreError::Unavailable));
        assert_eq!(
            reconciled.expect("reconciliation request").as_str(),
            "operation-e2e"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_receive_preserves_exact_operation_for_receipt_lookup() {
        let (error, reconciled) = apply_with_fake_boundary(UnknownBoundary::Receive).await;
        assert!(matches!(error, StoreError::Unavailable));
        assert_eq!(
            reconciled.expect("reconciliation request").as_str(),
            "operation-e2e"
        );
    }

    fn unix_ms() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    }
}
