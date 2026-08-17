#![forbid(unsafe_code)]

//! Composition owner for the S-03 canonical store bridge.
//!
//! This process exposes only the store-neutral EBP contract.  `SurrealDB`
//! credentials, provider transport and query text stay inside
//! `eliot-store-surreal-adapter`; this root only assembles the adapter and
//! serializes bounded contract receipts. Blob contributes one process/root
//! claim identity; it is not a second store or semantic write path.

use std::collections::BTreeSet;
use std::path::Path;

use eliot_blob::BlobRootOwner;
use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_ipc::{ReplayDisposition, ReplayLedger, TransportLimits};
use eliot_kernel_service::{
    HostStoreBootstrapRequirement, STORE_MODULE_IDENTITY, STORE_ROUTE_IDENTITY,
};
use eliot_platform::{ClockObservation, PlatformHandle};
use eliot_platform_windows::{
    NamedPipePeerExpectation, UserOwnedPathLease, UserOwnedRootLease, WindowsPlatform,
    read_protected_file,
};
use eliot_protocol::{
    ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolRange,
    ProtocolVersion, ServerHello,
};
use eliot_store_api::{
    CAPABILITIES, CanonicalStoreClient, CanonicalValidationSnapshot, EFFECTS, NamedReadRequest,
    NamedReadResponse, OperationId, OrderingHead, OrderingHeadExpectation, OrderingScopeId,
    PreparedTransition, RequestMeta, RevisionHead, RevisionHeadExpectation, RevisionKey,
    StoreError, StoreHealth, WriteReceipt, decode_request_frame,
};
pub use eliot_store_api::{ReadinessReceipt, StoreRequest as Request, StoreResponse as Response};
use eliot_store_surreal_adapter::{
    AdapterError, MigrationReceipt, PINNED_SURREALDB_MAJOR, SchemaGeneration, SemanticReadiness,
    SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const SERVICE_NAME: &str = "eliot-store-surreal";
pub const PROTOCOL_VERSION: &str = "eliot.s03.ebp.v1";
const MAX_LAUNCH_CONFIG_BYTES: u64 = 256 * 1024;

/// Error returned by the neutral Store root while preserving an ambiguous
/// provider write identity for the EBP response boundary.
#[derive(Debug, Error)]
pub enum StoreCompositionError {
    /// A deterministic store/API failure.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// The provider crossed a write boundary without proving its outcome.
    #[error("provider outcome is unknown for operation {operation_id}: {reason}")]
    UnknownOutcome {
        /// Exact operation identity used for receipt reconciliation.
        operation_id: OperationId,
        /// Bounded provider reason, not a success claim.
        reason: String,
    },
}

fn map_adapter_error(error: AdapterError) -> StoreCompositionError {
    match error {
        AdapterError::UnknownOutcome { operation_id } => match OperationId::new(operation_id) {
            Ok(operation_id) => StoreCompositionError::UnknownOutcome {
                operation_id,
                reason: "provider outcome is unknown; reconcile by exact receipt".to_owned(),
            },
            Err(error) => StoreCompositionError::Store(StoreError::Foundation(error)),
        },
        AdapterError::Store(error) => StoreCompositionError::Store(error),
        other => StoreCompositionError::Store(other.into_store_error()),
    }
}

/// Explicit, target-only process launch configuration.
///
/// This is intentionally not the legacy governor configuration.  The process
/// accepts only the connection coordinates, bounded timeouts, schema
/// generation, one Blob root, one process identity, and an opaque credential
/// reference.  Credential bytes are resolved after validation and never cross
/// this type or the EBP wire surface.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreLaunchConfig {
    pub store_pipe: String,
    /// Host-issued nonce for this exact Store process lineage.
    pub launch_nonce: String,
    /// SID/session the Store pipe must authenticate as its Kernel client.
    pub expected_client_sid: String,
    pub expected_client_session_id: u32,
    pub approved_artifact_hash: String,
    pub approved_config_hash: String,
    pub store_generation: u64,
    pub authority_epoch: u64,
    pub endpoint: String,
    pub namespace: String,
    pub database: String,
    pub username: String,
    pub connect_timeout_ms: u64,
    pub query_timeout_ms: u64,
    pub schema_generation: String,
    pub blob_root: String,
    pub instance_id: String,
    pub credential_ref: String,
}

impl StoreLaunchConfig {
    /// Validates every process-owned launch field before opening a provider or
    /// claiming the Blob root. No defaults are admitted.
    pub fn validate(&self) -> Result<(), String> {
        validate_launch_text(&self.store_pipe, "store_pipe")?;
        validate_launch_text(&self.launch_nonce, "launch_nonce")?;
        eliot_ipc::validate_pipe_name(&self.store_pipe)
            .map_err(|error| format!("invalid store_pipe: {error}"))?;
        NamedPipePeerExpectation::new(
            self.expected_client_sid.clone(),
            self.expected_client_session_id,
        )
        .map_err(|error| format!("invalid expected peer: {error}"))?;
        validate_digest(&self.approved_artifact_hash, "approved_artifact_hash")?;
        validate_digest(&self.approved_config_hash, "approved_config_hash")?;
        if self.approved_config_hash != launch_config_digest(self)? {
            return Err(
                "approved_config_hash does not bind the operational launch configuration"
                    .to_owned(),
            );
        }
        if self.store_generation == 0 || self.authority_epoch == 0 {
            return Err("store_generation and authority_epoch must be non-zero".to_owned());
        }
        validate_launch_text(&self.endpoint, "endpoint")?;
        if !self.endpoint.starts_with("ws://") && !self.endpoint.starts_with("wss://") {
            return Err("endpoint must start with ws:// or wss://".to_owned());
        }
        validate_launch_text(&self.namespace, "namespace")?;
        validate_launch_text(&self.database, "database")?;
        validate_launch_text(&self.username, "username")?;
        validate_launch_text(&self.schema_generation, "schema_generation")?;
        validate_launch_text(&self.blob_root, "blob_root")?;
        validate_launch_text(&self.instance_id, "instance_id")?;
        validate_launch_text(&self.credential_ref, "credential_ref")?;
        if self.connect_timeout_ms == 0 || self.query_timeout_ms == 0 {
            return Err("connect_timeout_ms and query_timeout_ms must be non-zero".to_owned());
        }
        SchemaGeneration::new(self.schema_generation.as_str())
            .map_err(|error| format!("invalid schema_generation: {error}"))?;
        if !Path::new(&self.blob_root).is_absolute() {
            return Err("blob_root must be an absolute path".to_owned());
        }
        Ok(())
    }
}

/// Constructs the exact store-neutral bootstrap descriptor consumed by
/// Kernel from this boundary's already-validated concrete launch config.
///
/// Concrete endpoint, namespace, database, credential and Blob fields never
/// cross this seam. The descriptor binds only the route/fence, authenticated
/// pipe peer, approved digests, launch identity and bounded timeout.
pub fn store_bootstrap_descriptor(
    config: &StoreLaunchConfig,
) -> Result<HostStoreBootstrapRequirement, String> {
    config.validate()?;
    let authority_epoch = AuthorityEpoch::new(config.authority_epoch)
        .map_err(|error| format!("invalid Store authority epoch: {error}"))?;
    let store_generation = ResourceGeneration::new(config.store_generation)
        .map_err(|error| format!("invalid Store generation: {error}"))?;
    let handle = |value: &str, field: &str| {
        PlatformHandle::new(value).map_err(|error| format!("invalid {field}: {error}"))
    };
    let connection_id = format!(
        "kernel-store:{}:{}",
        config.instance_id, config.launch_nonce
    );
    Ok(HostStoreBootstrapRequirement {
        route_identity: handle(STORE_ROUTE_IDENTITY, "route identity")?,
        canonical_pipe_identity: handle(&config.store_pipe, "canonical pipe identity")?,
        store_generation,
        state_fence: StateFence::new(authority_epoch, store_generation),
        launch_nonce: handle(&config.launch_nonce, "launch nonce")?,
        connection_id: handle(&connection_id, "connection identity")?,
        expected_peer_sid: handle(&config.expected_client_sid, "Store peer SID")?,
        expected_peer_session_id: config.expected_client_session_id,
        approved_artifact_hash: handle(&config.approved_artifact_hash, "Store artifact digest")?,
        approved_config_hash: handle(&config.approved_config_hash, "Store config digest")?,
        timeout_ms: config.connect_timeout_ms,
    })
}

/// Computes the Host-approved digest over every operational launch field.
/// The digest field itself is deliberately excluded to prevent self-reference.
pub fn launch_config_digest(config: &StoreLaunchConfig) -> Result<String, String> {
    #[derive(Serialize)]
    struct OperationalConfig<'a> {
        store_pipe: &'a str,
        launch_nonce: &'a str,
        expected_client_sid: &'a str,
        expected_client_session_id: u32,
        approved_artifact_hash: &'a str,
        store_generation: u64,
        authority_epoch: u64,
        endpoint: &'a str,
        namespace: &'a str,
        database: &'a str,
        username: &'a str,
        connect_timeout_ms: u64,
        query_timeout_ms: u64,
        schema_generation: &'a str,
        blob_root: &'a str,
        instance_id: &'a str,
        credential_ref: &'a str,
    }
    let input = OperationalConfig {
        store_pipe: &config.store_pipe,
        launch_nonce: &config.launch_nonce,
        expected_client_sid: &config.expected_client_sid,
        expected_client_session_id: config.expected_client_session_id,
        approved_artifact_hash: &config.approved_artifact_hash,
        store_generation: config.store_generation,
        authority_epoch: config.authority_epoch,
        endpoint: &config.endpoint,
        namespace: &config.namespace,
        database: &config.database,
        username: &config.username,
        connect_timeout_ms: config.connect_timeout_ms,
        query_timeout_ms: config.query_timeout_ms,
        schema_generation: &config.schema_generation,
        blob_root: &config.blob_root,
        instance_id: &config.instance_id,
        credential_ref: &config.credential_ref,
    };
    let bytes =
        serde_json::to_vec(&input).map_err(|error| format!("serialize launch digest: {error}"))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

fn validate_digest(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("{field} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_launch_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(format!(
            "{field} must be non-blank and contain no control characters"
        ));
    }
    Ok(())
}

/// Canonical store composition. All provider authority is held by the one
/// adapter and one process/root Blob claim; Blob does not become a semantic
/// store or alternate transition path.
pub struct StoreComposition {
    store: SurrealStoreAdapter,
    blob: BlobRootOwner,
    state_fence: StateFence,
}

impl std::fmt::Debug for StoreComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreComposition")
            .field("store", &self.store)
            .field("blob_owner", &self.blob)
            .field("state_fence", &self.state_fence)
            .finish()
    }
}

impl StoreComposition {
    /// Builds the adapter from the explicit target launch configuration.
    /// Credential bytes are read only inside this process from the configured
    /// Windows Credential Manager reference and are retained only by the
    /// adapter's redacted `SecretString` configuration.
    pub fn new(config: &StoreLaunchConfig) -> Result<Self, String> {
        config.validate()?;
        let blob = BlobRootOwner::claim(
            config.blob_root.clone(),
            format!("store-composition:{}", config.instance_id),
            std::process::id(),
        )
        .map_err(|error| format!("claim Blob root owner: {error}"))?;
        let platform = WindowsPlatform::new(config.blob_root.clone())
            .map_err(|error| format!("validate Blob root for credential access: {error}"))?;
        let password = resolve_credential(&platform, &config.credential_ref)?;
        let state_fence = StateFence::new(
            AuthorityEpoch::new(config.authority_epoch)
                .map_err(|error| format!("invalid Store authority epoch: {error}"))?,
            ResourceGeneration::new(config.store_generation)
                .map_err(|error| format!("invalid Store generation: {error}"))?,
        );
        state_fence
            .validate()
            .map_err(|error| format!("invalid Store state fence: {error}"))?;
        let store = SurrealStoreAdapter::new(adapter_config(config, password)?);
        Ok(Self {
            store,
            blob,
            state_fence,
        })
    }

    /// Rejects attempts to add a second process/root owner after composition.
    pub fn with_blob_owner(self, _owner: BlobRootOwner) -> Result<Self, String> {
        Err("exactly one Blob root owner is composed by StoreComposition::new".to_owned())
    }

    /// Returns the sole process/root claim identity. It carries no semantic
    /// write authority and does not mint Blob receipts.
    #[must_use]
    pub fn blob_owner(&self) -> &BlobRootOwner {
        &self.blob
    }

    /// Bounded adapter/provider health observation.
    pub async fn health(&self) -> Result<StoreHealth, StoreError> {
        self.store.health().await
    }

    /// Semantic schema readiness observation.  This is not a write authority
    /// verdict and is returned as its own receipt/status surface.
    pub async fn readiness(&self) -> Result<ReadinessReceipt, StoreError> {
        let readiness = self
            .store
            .probe_readiness()
            .await
            .map_err(AdapterError::into_store_error)?;
        if matches!(readiness, SemanticReadiness::Ready { .. }) {
            let snapshot = self.store.validation_snapshot().await?;
            snapshot.validate()?;
            if snapshot.state_fence != self.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        Ok(match readiness {
            SemanticReadiness::Unavailable => ReadinessReceipt::unavailable(),
            SemanticReadiness::MigrationRequired { expected, observed } => {
                ReadinessReceipt::migration_required(expected.to_string(), observed)
            }
            SemanticReadiness::Ready { generation } => {
                ReadinessReceipt::ready(generation.to_string())
            }
        })
    }

    /// Applies exactly the adapter's explicit first-generation schema plan.
    /// Normal Store startup never calls this method; portable development must
    /// opt into the separate schema-initialization CLI mode.
    pub async fn apply_initial_schema_migration(
        &self,
        observed_clock: &ClockObservation,
    ) -> Result<MigrationReceipt, StoreCompositionError> {
        let generation = self.store.config().expected_schema_generation.clone();
        let migration = SurrealStoreAdapter::initial_schema_migration(generation);
        self.store
            .apply_migration(&migration, observed_clock, &self.state_fence)
            .await
            .map_err(map_adapter_error)
    }

    /// Executes one closed named read from the store API catalogue.
    pub async fn named(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, eliot_store_api::StoreError> {
        self.store.execute_named(request).await
    }

    /// Applies one fully prepared transition through the sole canonical write
    /// path and returns the immutable transport receipt.
    pub async fn apply(
        &self,
        context: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreCompositionError> {
        context
            .validate()
            .map_err(StoreError::Foundation)
            .map_err(StoreCompositionError::Store)?;
        transition
            .validate()
            .map_err(StoreCompositionError::Store)?;
        if context.state_fence != transition.state_fence {
            return Err(StoreCompositionError::Store(StoreError::FenceMismatch));
        }
        self.store
            .apply_prepared(
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
            .map_err(map_adapter_error)
    }

    /// Reconciles a possibly ambiguous write by exact operation identity.
    pub async fn receipt(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<WriteReceipt>, StoreError> {
        self.store
            .reconcile(operation_id)
            .await
            .map_err(AdapterError::into_store_error)
    }

    /// Reads revision heads through the neutral store boundary.
    pub async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        self.store.revision_heads(keys).await
    }

    /// Reads one coherent canonical validation snapshot.
    pub async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        self.store.validation_snapshot().await
    }

    /// Reads ordering heads through the neutral store boundary.
    pub async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        self.store.ordering_heads(scopes).await
    }

    /// Returns the immutable closed operation manifest digest for the ready
    /// response; no provider-specific data is exposed.
    pub fn operation_manifest_digest(&self) -> &str {
        self.store.operation_manifest().digest.as_str()
    }
}

/// Immutable identity projected into the S-03 `ServerHello`.  The transport
/// loop does not get to invent any provider or process authority; it receives
/// this projection from the one `StoreComposition`.
#[derive(Clone, Debug)]
pub struct StoreHandshakeIdentity {
    operation_manifest_digest: String,
    blob_root_owner: serde_json::Value,
}

impl StoreHandshakeIdentity {
    /// Creates the bounded identity projection for one admitted composition.
    #[must_use]
    pub fn new(
        operation_manifest_digest: impl Into<String>,
        blob_root_owner: serde_json::Value,
    ) -> Self {
        Self {
            operation_manifest_digest: operation_manifest_digest.into(),
            blob_root_owner,
        }
    }
}

/// Authenticated S-03 session state retained by the Store transport loop.
///
/// The fields are intentionally private. Callers can obtain only the
/// negotiated transport values needed to send a response; request admission
/// remains inside [`validate_request_frame`].
pub struct StoreEbpSession {
    connection_id: String,
    protocol_version: ProtocolVersion,
    state_fence: StateFence,
    max_frame_bytes: usize,
    capabilities: BTreeSet<String>,
    replay: ReplayLedger,
}

impl StoreEbpSession {
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

/// Admits the only supported S-03 `ClientHello` and binds the complete
/// generation/fence/epoch lineage to the resulting session.
pub fn admit_handshake(
    frame: Frame,
    limits: TransportLimits,
    config: &StoreLaunchConfig,
    identity: &StoreHandshakeIdentity,
) -> Result<(StoreEbpSession, ServerHello), String> {
    config.validate()?;
    frame
        .validate()
        .map_err(|error| format!("validate EBP hello frame: {error}"))?;
    if frame.encoding_profile != EncodingProfile::JsonV1
        || frame.kind != FrameKind::Control
        || frame.message_type != MessageType::Start
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return Err("first frame must be an uncorrelated json-v1 Control/Start hello".to_owned());
    }
    let ProtocolPayload::Json(payload) = frame.payload else {
        return Err("EBP hello payload must use json-v1".to_owned());
    };
    let hello: ClientHello =
        serde_json::from_value(payload).map_err(|error| format!("decode ClientHello: {error}"))?;
    hello
        .validate()
        .map_err(|error| format!("validate ClientHello: {error}"))?;
    if hello.module_bridge_identity != STORE_MODULE_IDENTITY {
        return Err(format!(
            "ClientHello module_bridge_identity must be {STORE_MODULE_IDENTITY}"
        ));
    }
    let state_fence = &hello.module_generation.state_fence;
    if hello.artifact_hash.as_str() != config.approved_artifact_hash
        || hello.launch_nonce != config.launch_nonce
        || hello.module_generation.generation.value() != config.store_generation
        || state_fence.resource_generation != hello.module_generation.generation
        || state_fence.resource_generation.value() != config.store_generation
        || state_fence.authority_epoch != hello.authority_epoch
        || state_fence.authority_epoch.value() != config.authority_epoch
    {
        return Err(
            "ClientHello is outside the Host-approved store generation/fence lineage".to_owned(),
        );
    }
    if identity.operation_manifest_digest.trim().is_empty() {
        return Err("store operation manifest digest is empty".to_owned());
    }
    let server_range = ProtocolRange {
        minimum: ProtocolVersion::CURRENT,
        maximum: ProtocolVersion::CURRENT,
    };
    let protocol_version = hello
        .protocol_range
        .select(server_range)
        .map_err(|error| format!("negotiate EBP version: {error}"))?;
    if usize::try_from(hello.max_frame).unwrap_or(usize::MAX) > limits.max_frame_bytes {
        return Err("ClientHello max_frame exceeds the bounded transport limit".to_owned());
    }
    let capabilities: Vec<String> = CAPABILITIES
        .iter()
        .filter(|capability| hello.capabilities.iter().any(|value| value == **capability))
        .map(|capability| (*capability).to_owned())
        .collect();
    let effects: Vec<String> = EFFECTS.iter().map(|effect| (*effect).to_owned()).collect();
    let server_hello = ServerHello {
        selected_protocol: protocol_version,
        session_principal_binding: format!("{SERVICE_NAME}:{}", std::process::id()),
        allowed_capabilities: capabilities.clone(),
        allowed_effects: effects,
        config_snapshot: serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "artifact_hash": config.approved_artifact_hash,
            "config_hash": config.approved_config_hash,
            "operation_manifest_digest": identity.operation_manifest_digest,
            "blob_root_owner": identity.blob_root_owner,
        }),
        heartbeat_ms: 30_000,
        control_channel: "named_pipe".to_owned(),
        rejection_reason: None,
        authority_epoch: hello.authority_epoch,
    };
    server_hello
        .validate()
        .map_err(|error| format!("validate ServerHello: {error}"))?;
    Ok((
        StoreEbpSession {
            connection_id: frame.connection_id,
            protocol_version,
            state_fence: state_fence.clone(),
            max_frame_bytes: usize::try_from(hello.max_frame)
                .map_err(|_| "ClientHello max_frame does not fit usize".to_owned())?,
            capabilities: capabilities.into_iter().collect(),
            replay: ReplayLedger::default(),
        },
        server_hello,
    ))
}

/// Validates one request against the admitted session and replay ledger.
pub fn validate_request_frame(
    session: &mut StoreEbpSession,
    frame: &Frame,
) -> Result<Request, String> {
    if frame.protocol_version != session.protocol_version
        || frame.connection_id != session.connection_id
    {
        return Err("request frame is outside the negotiated EBP session".to_owned());
    }
    let (request_id, identity, request) =
        decode_request_frame(frame).map_err(|error| error.to_string())?;
    if identity.request.state_fence != session.state_fence {
        return Err("request identity state fence does not match the handshake fence".to_owned());
    }
    match session.replay.observe(request_id.to_string(), frame) {
        ReplayDisposition::Conflict => {
            return Err("request identity conflicts with a prior frame".to_owned());
        }
        ReplayDisposition::New | ReplayDisposition::Duplicate => {}
    }
    let capability = request.capability();
    if !session.capabilities.contains(capability) {
        return Err(format!("capability is not admitted: {capability}"));
    }
    Ok(request)
}

/// Store backend used by the reusable EBP request dispatch seam.
#[allow(async_fn_in_trait)]
pub trait StoreDispatchBackend: Send + Sync {
    /// Executes one already session-validated closed store request.
    async fn dispatch_request(&self, request: Request) -> Response;
}

/// Dispatches through the same production backend seam used by the binary
/// loop. Tests may provide a bounded fake backend without copying transport,
/// handshake, replay, or request validation authority.
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
        }
    }
}

fn adapter_config(
    config: &StoreLaunchConfig,
    password: SecretString,
) -> Result<SurrealAdapterConfig, String> {
    let schema_generation = SchemaGeneration::new(config.schema_generation.as_str())
        .map_err(|error| error.to_string())?;
    Ok(SurrealAdapterConfig {
        endpoint: config.endpoint.clone(),
        namespace: config.namespace.clone(),
        database: config.database.clone(),
        username: config.username.clone(),
        password,
        connect_timeout_ms: config.connect_timeout_ms,
        query_timeout_ms: config.query_timeout_ms,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: schema_generation,
    })
}

fn resolve_credential(
    platform: &WindowsPlatform,
    credential_ref: &str,
) -> Result<SecretString, String> {
    let credential = platform
        .read_credential(credential_ref)
        .map_err(|error| format!("read configured credential reference: {error}"))?;
    let password = String::from_utf8(credential.expose().to_vec())
        .map_err(|_| "configured credential is not UTF-8".to_owned())?;
    non_empty_secret(&password, "configured credential")
}

fn non_empty_secret(value: &str, source: &str) -> Result<SecretString, String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(format!("{source} is empty"));
    }
    Ok(SecretString::new(value.into()))
}

/// Loads the process's explicit non-secret launch configuration from the
/// protected `ProgramData` contour. Secret material is resolved from the opaque
/// credential reference only inside `StoreComposition::new`. Missing or
/// out-of-contour configuration is an error; there is no default or legacy
/// configuration conversion.
pub fn load_config(path: Option<&Path>) -> Result<StoreLaunchConfig, String> {
    let Some(path) = path else {
        return Err("--config is required; launch config must be explicit".to_owned());
    };
    let bytes = read_protected_file(path, MAX_LAUNCH_CONFIG_BYTES)
        .map_err(|error| format!("read protected config: {error}"))?;
    parse_config_bytes(path, &bytes)
}

/// Loads a portable-development launch configuration through a retained
/// user-owned root and file lease.  The lease is the only read surface: the
/// path must remain inside the caller-provided existing root and the bytes are
/// bounded before deserialization.
pub fn load_portable_dev_config(
    root: &UserOwnedRootLease,
    path: &Path,
) -> Result<StoreLaunchConfig, String> {
    let lease = UserOwnedPathLease::open_existing(root, path)
        .map_err(|error| format!("open portable-dev config: {error}"))?;
    let bytes = lease
        .read_bounded(MAX_LAUNCH_CONFIG_BYTES)
        .map_err(|error| format!("read portable-dev config: {error}"))?;
    parse_config_bytes(path, &bytes)
}

fn parse_config_bytes(path: &Path, bytes: &[u8]) -> Result<StoreLaunchConfig, String> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => {
            let config: StoreLaunchConfig = serde_json::from_slice(bytes)
                .map_err(|error| format!("parse JSON config: {error}"))?;
            config.validate()?;
            Ok(config)
        }
        Some("toml") => {
            let config: StoreLaunchConfig =
                toml::from_slice(bytes).map_err(|error| format!("parse TOML config: {error}"))?;
            config.validate()?;
            Ok(config)
        }
        Some(extension) => Err(format!(
            "config extension must be .json or .toml, got .{extension}"
        )),
        None => Err("config path must have a .json or .toml extension".to_owned()),
    }
}

#[cfg(test)]
// Test fixtures intentionally fail immediately when their static identities are invalid.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, AuthorityEpoch, ContractId, ContractVersion, ResourceGeneration,
    };
    use eliot_runtime_contracts::{
        HealthVector, ModuleContract, ModuleGeneration, ModuleGenerationState,
    };

    fn config() -> StoreLaunchConfig {
        let mut config = StoreLaunchConfig {
            store_pipe: r"\\.\pipe\eliot\store-test".to_owned(),
            launch_nonce: "launch-test".to_owned(),
            expected_client_sid: "S-1-5-18".to_owned(),
            expected_client_session_id: 0,
            approved_artifact_hash: "a".repeat(64),
            approved_config_hash: String::new(),
            store_generation: 1,
            authority_epoch: 1,
            endpoint: "ws://127.0.0.1:8000".to_owned(),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: "store".to_owned(),
            connect_timeout_ms: 1_000,
            query_timeout_ms: 1_000,
            schema_generation: "1.0.0".to_owned(),
            blob_root: r"C:\ProgramData\Eliot\blob".to_owned(),
            instance_id: "store-test".to_owned(),
            credential_ref: "eliot/store".to_owned(),
        };
        config.approved_config_hash = launch_config_digest(&config).expect("config digest");
        config
    }

    #[test]
    fn launch_nonce_and_operational_fields_are_digest_bound() {
        let config = config();
        assert!(config.validate().is_ok());
        let mut altered = config.clone();
        altered.launch_nonce = "different-launch".to_owned();
        assert!(altered.validate().is_err());
        let mut endpoint_altered = config;
        endpoint_altered.endpoint = "ws://127.0.0.1:9000".to_owned();
        assert!(endpoint_altered.validate().is_err());
    }

    #[test]
    fn neutral_descriptor_excludes_concrete_provider_configuration() {
        let config = config();
        let descriptor = store_bootstrap_descriptor(&config).expect("neutral descriptor");
        descriptor.validate().expect("descriptor validates");
        assert_eq!(descriptor.route_identity.as_str(), STORE_ROUTE_IDENTITY);
        assert_eq!(
            descriptor.canonical_pipe_identity.as_str(),
            config.store_pipe
        );
        assert_eq!(descriptor.timeout_ms, config.connect_timeout_ms);
        let encoded = serde_json::to_value(&descriptor).expect("descriptor JSON");
        for forbidden in [
            "endpoint",
            "namespace",
            "database",
            "username",
            "credential_ref",
            "blob_root",
            "schema_generation",
        ] {
            assert!(encoded.get(forbidden).is_none(), "leaked {forbidden}");
        }
    }

    #[test]
    fn bounded_config_parser_supports_json_and_rejects_other_extensions() {
        let config = config();
        let json = serde_json::to_vec(&config).expect("JSON config");
        let parsed =
            parse_config_bytes(Path::new("store.json"), &json).expect("JSON config parses");
        assert_eq!(parsed.store_pipe, config.store_pipe);
        assert_eq!(parsed.approved_config_hash, config.approved_config_hash);
        assert!(parse_config_bytes(Path::new("store.txt"), &json).is_err());
    }

    #[test]
    fn unknown_provider_outcome_keeps_exact_wire_operation() {
        let error = map_adapter_error(AdapterError::UnknownOutcome {
            operation_id: "operation-test".to_owned(),
        });
        assert!(matches!(
            error,
            StoreCompositionError::UnknownOutcome { operation_id, .. }
                if operation_id.as_str() == "operation-test"
        ));
    }

    fn client_hello_frame(config: &StoreLaunchConfig) -> Frame {
        let module_id = ContractId::new(STORE_MODULE_IDENTITY).expect("module id");
        let artifact_id =
            ArtifactId::new(config.approved_artifact_hash.as_str()).expect("artifact");
        let authority_epoch = AuthorityEpoch::new(config.authority_epoch).expect("epoch");
        let generation = ResourceGeneration::new(config.store_generation).expect("generation");
        let hello = ClientHello {
            protocol_range: ProtocolRange {
                minimum: ProtocolVersion::CURRENT,
                maximum: ProtocolVersion::CURRENT,
            },
            module_bridge_identity: STORE_MODULE_IDENTITY.to_owned(),
            artifact_hash: artifact_id.clone(),
            module_contract: ModuleContract {
                module_id: module_id.clone(),
                version: ContractVersion::new(1, 0, 0),
                artifact_id: artifact_id.clone(),
                protocols: vec![PROTOCOL_VERSION.to_owned()],
                required_capabilities: vec!["store.readiness".to_owned()],
                optional_capabilities: Vec::new(),
                advisory_capabilities: Vec::new(),
                state_owner: "eliot-kernel".to_owned(),
                failure_domain: SERVICE_NAME.to_owned(),
                hot_replace: false,
            },
            module_generation: ModuleGeneration {
                module_id,
                generation,
                artifact_id,
                state: ModuleGenerationState::Active,
                health: HealthVector::healthy(),
                state_fence: StateFence::new(authority_epoch, generation),
            },
            launch_nonce: config.launch_nonce.clone(),
            capabilities: CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            privacy_classes: vec!["PUBLIC".to_owned()],
            max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
                .expect("protocol frame limit fits the wire field"),
            authority_epoch,
        };
        eliot_ipc::client_hello_frame("connection-test", &hello).expect("hello frame")
    }

    #[test]
    fn handshake_rejects_partial_generation_or_fence_lineage() {
        let config = config();
        let identity = StoreHandshakeIdentity::new("manifest-test", serde_json::json!({}));
        let frame = client_hello_frame(&config);
        assert!(
            admit_handshake(
                frame.clone(),
                TransportLimits::default(),
                &config,
                &identity,
            )
            .is_ok()
        );

        let ProtocolPayload::Json(payload) = frame.payload else {
            panic!("hello payload");
        };
        let mut hello: ClientHello = serde_json::from_value(payload).expect("client hello");
        hello.module_generation.state_fence = StateFence::new(
            AuthorityEpoch::new(config.authority_epoch).expect("epoch"),
            ResourceGeneration::new(config.store_generation + 1).expect("generation"),
        );
        let mismatched =
            eliot_ipc::client_hello_frame("connection-test", &hello).expect("mismatched hello");
        assert!(
            admit_handshake(mismatched, TransportLimits::default(), &config, &identity,).is_err()
        );

        let mismatched_authority = AuthorityEpoch::new(config.authority_epoch + 1).expect("epoch");
        hello.authority_epoch = mismatched_authority;
        hello.module_generation.state_fence = StateFence::new(
            mismatched_authority,
            ResourceGeneration::new(config.store_generation).expect("generation"),
        );
        let mismatched_epoch = eliot_ipc::client_hello_frame("connection-test", &hello)
            .expect("mismatched epoch hello");
        assert!(
            admit_handshake(
                mismatched_epoch,
                TransportLimits::default(),
                &config,
                &identity,
            )
            .is_err()
        );
    }
}
