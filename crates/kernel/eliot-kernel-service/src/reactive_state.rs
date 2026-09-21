//! Authenticated Kernel front-door handler for canonical reactive state
//! (issue #1941 C4).
//!
//! This module is the authority/fence/operation boundary for reactive
//! ledger and resource-snapshot writes and reads: it binds an
//! authenticated session from live Kernel state, validates the protected
//! request (identity, fence, operation identity, canonical request hash),
//! dispatches exactly once through the existing [`CanonicalStoreClient`]
//! path, validates the exact store response receipt, and maps
//! unsupported/unavailable/unknown outcomes without claiming success.
//! Ledger bytes stay opaque (delivery semantics live in the bridge
//! ledger); snapshot digests are recomputed by the Store backend, never
//! trusted from the caller. This service never invents delivery,
//! stickiness, or resolution.

use eliot_contracts::{EpochId, ResourceGeneration, StateFence};
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, EffectClass, EventProjectionRelationIntents,
    OperationId, OperationManifestDigest, OrderingScopeId, PreparedTransition, ReceiptEnvelope,
    RequestMetadata, ScopeId, SecurityContext, StoreError, TransitionClass, WriteReceiptStatus,
    canonical_json_bytes, generated_operation_manifests, operation_manifest_set_digest,
    reactive_ledger_mutation_request, reactive_ledger_read_request,
    resource_snapshot_mutation_request, resource_snapshot_read_request, sha256_hex,
    verify_canonical_request_hash,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{KernelService, KernelServiceError, KernelServiceState, validate_text};

/// Authenticated reactive session bound from live Kernel state.
#[derive(Clone, Debug)]
pub struct AuthenticatedReactiveSession {
    principal: String,
    authority_epoch: EpochId,
    generation: u64,
}

impl AuthenticatedReactiveSession {
    /// Binds one reactive session from live Kernel state.
    ///
    /// Fails closed when the generation is fenced, the service is not
    /// `Ready`, no candidate lineage or consumed activation receipt exists,
    /// the activation no longer agrees with the live epoch (revoked/stale
    /// activation), or the principal reference is not bounded wire text.
    pub fn bind(service: &KernelService, principal_ref: &str) -> Result<Self, KernelServiceError> {
        validate_text(principal_ref, "reactive.principal")?;
        if service.generation_fenced() {
            return Err(KernelServiceError::GenerationFenced);
        }
        let state = service.state();
        if state != KernelServiceState::Ready {
            return Err(KernelServiceError::AdmissionClosed(state));
        }
        let candidate =
            service
                .candidate_binding()
                .ok_or(KernelServiceError::HandshakeMismatch {
                    field: "missing_candidate",
                })?;
        let activation =
            service
                .activation_receipt()
                .ok_or(KernelServiceError::HandshakeMismatch {
                    field: "missing_activation",
                })?;
        let live_epoch = service.authority_epoch();
        if !candidate.kernel_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "reactive.authority_epoch",
            });
        }
        if !activation.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "reactive.authority_epoch",
            });
        }
        Ok(Self {
            principal: principal_ref.to_owned(),
            authority_epoch: live_epoch,
            generation: activation.generation.value(),
        })
    }

    /// Returns the authenticated principal reference.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Builds the live service context; the presented fence must agree with it.
    pub fn service_context(
        &self,
        service: &KernelService,
    ) -> Result<ReactiveServiceContext, KernelServiceError> {
        if service.generation_fenced() {
            return Err(KernelServiceError::GenerationFenced);
        }
        let state = service.state();
        if state != KernelServiceState::Ready {
            return Err(KernelServiceError::AdmissionClosed(state));
        }
        let activation =
            service
                .activation_receipt()
                .ok_or(KernelServiceError::HandshakeMismatch {
                    field: "missing_activation",
                })?;
        let live_epoch = service.authority_epoch();
        if !activation.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "reactive.authority_epoch",
            });
        }
        if !self.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "reactive.authority_epoch",
            });
        }
        if self.generation != activation.generation.value() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "reactive.generation",
            });
        }
        Ok(ReactiveServiceContext {
            authority_epoch: live_epoch,
            generation: activation.generation.value(),
        })
    }
}

/// Live service authority a reactive request is admitted under.
#[derive(Clone, Debug)]
pub struct ReactiveServiceContext {
    /// Live authority epoch.
    pub authority_epoch: EpochId,
    /// Live activation generation.
    pub generation: u64,
}

/// Authenticated reactive-ledger write request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReactiveLedgerRequest {
    /// Exact operation identity (idempotency + canonical request hash).
    pub operation: eliot_store_api::OperationIdentity,
    /// Caller request metadata bound by the Kernel route.
    pub context: RequestMetadata,
    /// Fence the mutation is admitted under.
    pub state_fence: StateFence,
    /// Kernel-owned activation-sealed session binding.
    pub session_id: String,
    /// Opaque bridge ledger snapshot bytes as text.
    pub ledger_json: String,
}

/// Reactive-ledger write response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReactiveLedgerResponse {
    /// Owner revision after the mutation.
    pub revision: u64,
    /// Exact store response receipt (never fabricated by the caller).
    pub receipt: ReceiptEnvelope,
    /// True when the response replays an already-admitted operation identity.
    pub replayed: bool,
}

/// Authenticated resource-snapshot write request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSnapshotRequest {
    /// Exact operation identity (idempotency + canonical request hash).
    pub operation: eliot_store_api::OperationIdentity,
    /// Caller request metadata bound by the Kernel route.
    pub context: RequestMetadata,
    /// Fence the mutation is admitted under.
    pub state_fence: StateFence,
    /// Canonical `eliot://` resource identity.
    pub uri: String,
    /// Exact snapshot bytes.
    pub content: Vec<u8>,
}

/// Resource-snapshot write response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSnapshotResponse {
    /// Lowercase SHA-256 hex of the exact snapshot bytes.
    pub content_sha256: String,
    /// Owner revision after the mutation.
    pub revision: u64,
    /// Exact store response receipt (never fabricated by the caller).
    pub receipt: ReceiptEnvelope,
    /// True when the response replays an already-admitted operation identity.
    pub replayed: bool,
}

/// Same-fence canonical ledger read request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReactiveLedgerReadRequest {
    /// Caller request metadata bound by the Kernel route.
    pub context: RequestMetadata,
    /// Fence the projection is admitted under.
    pub state_fence: StateFence,
    /// Exact session selector.
    pub session_id: String,
}

/// Same-fence canonical ledger read response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReactiveLedgerReadResponse {
    /// Verbatim ledger snapshot, or `None` when absent.
    pub ledger_json: Option<String>,
    /// Owner revision the projection was read at.
    pub revision: u64,
    /// Fence the projection was admitted under.
    pub state_fence: StateFence,
}

/// Same-fence canonical snapshot read request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSnapshotReadRequest {
    /// Caller request metadata bound by the Kernel route.
    pub context: RequestMetadata,
    /// Fence the projection is admitted under.
    pub state_fence: StateFence,
    /// Exact canonical URI selector.
    pub uri: String,
}

/// Same-fence canonical snapshot read response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSnapshotReadResponse {
    /// Exact snapshot bytes, or `None` when absent.
    pub content: Option<Vec<u8>>,
    /// Lowercase SHA-256 hex of the served bytes, when present.
    pub content_sha256: Option<String>,
    /// Owner revision the projection was read at.
    pub revision: u64,
    /// Fence the projection was admitted under.
    pub state_fence: StateFence,
}

/// Front-door errors for reactive-state admission.
#[derive(Debug, Error)]
pub enum ReactiveServiceError {
    /// A field failed bounded identity validation.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason code.
        reason: &'static str,
    },
    /// The presented fence does not match live service authority.
    #[error("reactive state fence mismatch")]
    FenceMismatch,
    /// The operation identity collides with different executable bytes.
    #[error("reactive operation identity conflict")]
    IdentityConflict,
    /// The canonical request hash does not match the admitted bytes.
    #[error("reactive canonical request digest mismatch")]
    DigestMismatch,
    /// The store refused to commit the admitted transition.
    #[error("reactive transition was not committed")]
    NotCommitted,
    /// The store manifest digest does not match the admitted catalogue.
    #[error("reactive operation manifest mismatch")]
    ManifestMismatch,
    /// The store committed no response receipt; the outcome is unknown.
    #[error("reactive response receipt is missing; outcome is unknown")]
    MissingReceiptEnvelope,
    /// A closed store error.
    #[error("reactive store: {0}")]
    Store(#[from] StoreError),
    /// A Kernel service error.
    #[error("reactive service: {0}")]
    Service(#[from] KernelServiceError),
}

impl ReactiveServiceError {
    /// Maps a store error without manufacturing authority.
    pub fn from_store(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Handles one authenticated reactive-ledger write.
///
/// Dispatches exactly once through the existing [`CanonicalStoreClient`]
/// path and validates the exact store response receipt. Ledger bytes
/// travel opaquely; the backend verifies the contract stamp and bounds.
pub async fn handle_reactive_ledger_request(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedReactiveSession,
    request: &ReactiveLedgerRequest,
) -> Result<ReactiveLedgerResponse, ReactiveServiceError> {
    let context = session
        .service_context(service)
        .map_err(ReactiveServiceError::Service)?;
    validate_ledger_request(request)?;
    require_live_fence(&context, &request.state_fence)?;
    if request.context.state_fence != request.state_fence {
        return Err(ReactiveServiceError::FenceMismatch);
    }
    let meta = &request.context;
    let (transition, manifest_digest) = build_ledger_transition(request)?;
    let view = CanonicalRequestView::from_apply(meta, &transition, &[], &[]);
    verify_canonical_request_hash(&view, &request.operation.canonical_request_hash)
        .map_err(|_| ReactiveServiceError::DigestMismatch)?;
    if let Some(existing) = client
        .receipt(request.operation.operation_id.clone())
        .await
        .map_err(ReactiveServiceError::from_store)?
    {
        if existing.canonical_request_hash != request.operation.canonical_request_hash
            || existing.idempotency_key != request.operation.idempotency_key
        {
            return Err(ReactiveServiceError::IdentityConflict);
        }
        let revision =
            read_back_ledger_revision(client, &request.session_id, &request.state_fence).await?;
        let receipt = existing
            .require_reconciliation_envelope()
            .map_err(ReactiveServiceError::from_store)?
            .clone();
        return Ok(ReactiveLedgerResponse {
            revision,
            receipt,
            replayed: true,
        });
    }
    let receipt = client
        .apply_prepared(meta, transition, Vec::new(), Vec::new())
        .await
        .map_err(ReactiveServiceError::from_store)?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(ReactiveServiceError::NotCommitted);
    }
    receipt
        .validate()
        .map_err(ReactiveServiceError::from_store)?;
    if receipt.state_fence != request.state_fence {
        return Err(ReactiveServiceError::FenceMismatch);
    }
    if receipt.operation_manifest_digest != manifest_digest {
        return Err(ReactiveServiceError::ManifestMismatch);
    }
    let envelope = receipt
        .require_reconciliation_envelope()
        .map_err(ReactiveServiceError::from_store)?
        .clone();
    envelope
        .validate()
        .map_err(|_| ReactiveServiceError::MissingReceiptEnvelope)?;
    let revision =
        read_back_ledger_revision(client, &request.session_id, &request.state_fence).await?;
    Ok(ReactiveLedgerResponse {
        revision,
        receipt: envelope,
        replayed: false,
    })
}

/// Handles one authenticated reactive-ledger read.
///
/// Same-fence canonical projection only. Absent sessions project
/// explicit absence, never fabricated bytes.
pub async fn handle_reactive_ledger_read(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedReactiveSession,
    request: &ReactiveLedgerReadRequest,
) -> Result<ReactiveLedgerReadResponse, ReactiveServiceError> {
    let context = session
        .service_context(service)
        .map_err(ReactiveServiceError::Service)?;
    validate_text(&request.session_id, "reactive.session_id").map_err(|_| {
        ReactiveServiceError::InvalidField {
            field: "reactive.session_id",
            reason: "session must be bounded wire text",
        }
    })?;
    require_live_fence(&context, &request.state_fence)?;
    if request.context.state_fence != request.state_fence {
        return Err(ReactiveServiceError::FenceMismatch);
    }
    let query =
        reactive_ledger_read_request(request.session_id.clone(), request.state_fence.clone())
            .map_err(ReactiveServiceError::from_store)?;
    let payload = client
        .execute_named(query)
        .await
        .map_err(ReactiveServiceError::from_store)?;
    decode_ledger_read_response(&payload.payload, &request.state_fence)
}

/// Handles one authenticated resource-snapshot write.
///
/// Content bytes travel to the store builder, which base64-encodes them;
/// the backend re-decodes and re-hashes before persisting.
pub async fn handle_resource_snapshot_request(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedReactiveSession,
    request: &ResourceSnapshotRequest,
) -> Result<ResourceSnapshotResponse, ReactiveServiceError> {
    let context = session
        .service_context(service)
        .map_err(ReactiveServiceError::Service)?;
    validate_snapshot_request(request)?;
    require_live_fence(&context, &request.state_fence)?;
    if request.context.state_fence != request.state_fence {
        return Err(ReactiveServiceError::FenceMismatch);
    }
    let meta = &request.context;
    let (transition, manifest_digest, content_sha256) = build_snapshot_transition(request)?;
    let view = CanonicalRequestView::from_apply(meta, &transition, &[], &[]);
    verify_canonical_request_hash(&view, &request.operation.canonical_request_hash)
        .map_err(|_| ReactiveServiceError::DigestMismatch)?;
    if let Some(existing) = client
        .receipt(request.operation.operation_id.clone())
        .await
        .map_err(ReactiveServiceError::from_store)?
    {
        if existing.canonical_request_hash != request.operation.canonical_request_hash
            || existing.idempotency_key != request.operation.idempotency_key
        {
            return Err(ReactiveServiceError::IdentityConflict);
        }
        let revision =
            read_back_snapshot_revision(client, &request.uri, &request.state_fence).await?;
        let receipt = existing
            .require_reconciliation_envelope()
            .map_err(ReactiveServiceError::from_store)?
            .clone();
        return Ok(ResourceSnapshotResponse {
            content_sha256,
            revision,
            receipt,
            replayed: true,
        });
    }
    let receipt = client
        .apply_prepared(meta, transition, Vec::new(), Vec::new())
        .await
        .map_err(ReactiveServiceError::from_store)?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(ReactiveServiceError::NotCommitted);
    }
    receipt
        .validate()
        .map_err(ReactiveServiceError::from_store)?;
    if receipt.state_fence != request.state_fence {
        return Err(ReactiveServiceError::FenceMismatch);
    }
    if receipt.operation_manifest_digest != manifest_digest {
        return Err(ReactiveServiceError::ManifestMismatch);
    }
    let envelope = receipt
        .require_reconciliation_envelope()
        .map_err(ReactiveServiceError::from_store)?
        .clone();
    envelope
        .validate()
        .map_err(|_| ReactiveServiceError::MissingReceiptEnvelope)?;
    let revision = read_back_snapshot_revision(client, &request.uri, &request.state_fence).await?;
    Ok(ResourceSnapshotResponse {
        content_sha256,
        revision,
        receipt: envelope,
        replayed: false,
    })
}

/// Handles one authenticated resource-snapshot read.
pub async fn handle_resource_snapshot_read(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedReactiveSession,
    request: &ResourceSnapshotReadRequest,
) -> Result<ResourceSnapshotReadResponse, ReactiveServiceError> {
    let context = session
        .service_context(service)
        .map_err(ReactiveServiceError::Service)?;
    validate_text(&request.uri, "reactive.uri").map_err(|_| {
        ReactiveServiceError::InvalidField {
            field: "reactive.uri",
            reason: "uri must be bounded wire text",
        }
    })?;
    require_live_fence(&context, &request.state_fence)?;
    if request.context.state_fence != request.state_fence {
        return Err(ReactiveServiceError::FenceMismatch);
    }
    let query = resource_snapshot_read_request(request.uri.clone(), request.state_fence.clone())
        .map_err(ReactiveServiceError::from_store)?;
    let payload = client
        .execute_named(query)
        .await
        .map_err(ReactiveServiceError::from_store)?;
    decode_snapshot_read_response(&payload.payload, &request.state_fence)
}

/// Reconciles one exact admitted operation identity after transport loss.
pub async fn reconcile_reactive_state(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedReactiveSession,
    operation_id: OperationId,
    idempotency_key: &str,
    canonical_request_hash: &str,
) -> Result<Option<ReceiptEnvelope>, ReactiveServiceError> {
    let _context = session
        .service_context(service)
        .map_err(ReactiveServiceError::Service)?;
    validate_text(idempotency_key, "reactive.idempotency_key")?;
    validate_text(canonical_request_hash, "reactive.canonical_request_hash")?;
    let stored = client
        .receipt(operation_id)
        .await
        .map_err(ReactiveServiceError::from_store)?;
    match stored {
        Some(receipt)
            if receipt.idempotency_key == idempotency_key
                && receipt.canonical_request_hash == canonical_request_hash =>
        {
            let envelope = receipt
                .require_reconciliation_envelope()
                .map_err(ReactiveServiceError::from_store)?
                .clone();
            Ok(Some(envelope))
        }
        Some(_) => Err(ReactiveServiceError::IdentityConflict),
        None => Ok(None),
    }
}

fn validate_ledger_request(request: &ReactiveLedgerRequest) -> Result<(), ReactiveServiceError> {
    let invalid = |field: &'static str| ReactiveServiceError::InvalidField {
        field,
        reason: "reactive request failed closed validation",
    };
    request
        .operation
        .validate()
        .map_err(|_| invalid("reactive.operation"))?;
    validate_text(&request.session_id, "reactive.session_id")
        .map_err(|_| invalid("reactive.session_id"))?;
    if request.ledger_json.is_empty()
        || request.ledger_json.len() > eliot_store_api::MAX_REACTIVE_LEDGER_BYTES
    {
        return Err(invalid("reactive.ledger_json"));
    }
    Ok(())
}

fn validate_snapshot_request(
    request: &ResourceSnapshotRequest,
) -> Result<(), ReactiveServiceError> {
    let invalid = |field: &'static str| ReactiveServiceError::InvalidField {
        field,
        reason: "reactive request failed closed validation",
    };
    request
        .operation
        .validate()
        .map_err(|_| invalid("reactive.operation"))?;
    validate_text(&request.uri, "reactive.uri").map_err(|_| invalid("reactive.uri"))?;
    if request.content.is_empty()
        || request.content.len() > eliot_store_api::MAX_RESOURCE_CONTENT_BYTES
    {
        return Err(invalid("reactive.content"));
    }
    Ok(())
}

fn require_live_fence(
    context: &ReactiveServiceContext,
    fence: &StateFence,
) -> Result<(), ReactiveServiceError> {
    if !fence
        .authority_epoch
        .is_same_authority(&context.authority_epoch)
    {
        return Err(ReactiveServiceError::FenceMismatch);
    }
    let generation = ResourceGeneration::new(context.generation).map_err(|_| {
        ReactiveServiceError::InvalidField {
            field: "reactive.generation",
            reason: "live generation is not a valid resource generation",
        }
    })?;
    if fence.resource_generation != generation {
        return Err(ReactiveServiceError::FenceMismatch);
    }
    fence
        .validate()
        .map_err(|_| ReactiveServiceError::FenceMismatch)?;
    Ok(())
}

fn build_ledger_transition(
    request: &ReactiveLedgerRequest,
) -> Result<(PreparedTransition, OperationManifestDigest), ReactiveServiceError> {
    let operation =
        reactive_ledger_mutation_request(request.session_id.clone(), request.ledger_json.clone());
    build_reactive_transition(request, operation, || {
        OrderingScopeId::new(format!("reactive-session:{}", request.session_id)).map_err(|_| {
            ReactiveServiceError::InvalidField {
                field: "reactive.session_id",
                reason: "session ordering scope identity is invalid",
            }
        })
    })
}

fn build_snapshot_transition(
    request: &ResourceSnapshotRequest,
) -> Result<(PreparedTransition, OperationManifestDigest, String), ReactiveServiceError> {
    let operation = resource_snapshot_mutation_request(request.uri.clone(), &request.content)
        .map_err(ReactiveServiceError::from_store)?;
    let content_sha256 = operation
        .parameters
        .get(eliot_store_api::REACTIVE_PARAM_CONTENT_SHA256)
        .and_then(Value::as_str)
        .ok_or(ReactiveServiceError::InvalidField {
            field: "reactive.content_sha256",
            reason: "snapshot digest missing after build",
        })?
        .to_owned();
    let (transition, manifest_digest) = build_reactive_transition(request, operation, || {
        OrderingScopeId::new(format!("reactive-snapshot:{}", request.uri)).map_err(|_| {
            ReactiveServiceError::InvalidField {
                field: "reactive.uri",
                reason: "snapshot ordering scope identity is invalid",
            }
        })
    })?;
    Ok((transition, manifest_digest, content_sha256))
}

fn build_reactive_transition<R>(
    request: &R,
    operation: eliot_store_api::NamedMutationRequest,
    ordering: impl FnOnce() -> Result<OrderingScopeId, ReactiveServiceError>,
) -> Result<(PreparedTransition, OperationManifestDigest), ReactiveServiceError>
where
    R: ReactiveTransitionRequest,
{
    let manifest_digest = operation_manifest_set_digest(&generated_operation_manifests()?)
        .map_err(|_| ReactiveServiceError::ManifestMismatch)?;
    // The admission digest binds the admitted request with the identity-hash
    // field cleared: the hash itself is bound separately by the transition
    // view, so clearing keeps admission deterministic across sealing (which
    // fills the hash after building) and dispatch (which rebuilds from the
    // sealed request). A caller-supplied admission digest is never trusted.
    let mut admission_view = request.admission_view();
    admission_view.clear_hash();
    let admission_digest = sha256_hex(
        &canonical_json_bytes(&admission_view).map_err(|_| ReactiveServiceError::DigestMismatch)?,
    );
    let scope = ScopeId::new(eliot_store_api::REACTIVE_STATE_SCOPE).map_err(|_| {
        ReactiveServiceError::InvalidField {
            field: "reactive.scope",
            reason: "reactive scope identity is invalid",
        }
    })?;
    let transition = PreparedTransition {
        identity: request.operation().clone(),
        state_fence: request.fence().clone(),
        scope_id: scope,
        task_id: request.task_id(),
        ordering_scopes: vec![ordering()?],
        transition_class: TransitionClass::ReactiveState,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: admission_digest,
        operation_manifest_digest: manifest_digest.clone(),
        named_operations: vec![operation],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    transition
        .validate()
        .map_err(ReactiveServiceError::from_store)?;
    Ok((transition, manifest_digest))
}

/// Minimal request surface shared by both reactive transition builders.
trait ReactiveTransitionRequest {
    /// Exact operation identity.
    fn operation(&self) -> &eliot_store_api::OperationIdentity;
    /// Admission fence.
    fn fence(&self) -> &StateFence;
    /// Caller task binding, when present.
    fn task_id(&self) -> Option<String>;
    /// Canonical admission view for the digest.
    fn admission_view(&self) -> ReactiveAdmissionView;
}

/// Canonical admission view with a clearable identity hash.
#[derive(Clone, Debug, Serialize)]
struct ReactiveAdmissionView {
    context: RequestMetadata,
    state_fence: StateFence,
    session_id: String,
    ledger_json: String,
    uri: String,
    content: Vec<u8>,
    canonical_request_hash: String,
}

impl ReactiveAdmissionView {
    /// Clears the identity hash before admission digesting.
    fn clear_hash(&mut self) {
        self.canonical_request_hash = String::new();
    }
}

impl ReactiveTransitionRequest for ReactiveLedgerRequest {
    fn operation(&self) -> &eliot_store_api::OperationIdentity {
        &self.operation
    }

    fn fence(&self) -> &StateFence {
        &self.state_fence
    }

    fn task_id(&self) -> Option<String> {
        self.context.task_id.clone().map(|task| task.to_string())
    }

    fn admission_view(&self) -> ReactiveAdmissionView {
        ReactiveAdmissionView {
            context: self.context.clone(),
            state_fence: self.state_fence.clone(),
            session_id: self.session_id.clone(),
            ledger_json: self.ledger_json.clone(),
            uri: String::new(),
            content: Vec::new(),
            canonical_request_hash: self.operation.canonical_request_hash.clone(),
        }
    }
}

impl ReactiveTransitionRequest for ResourceSnapshotRequest {
    fn operation(&self) -> &eliot_store_api::OperationIdentity {
        &self.operation
    }

    fn fence(&self) -> &StateFence {
        &self.state_fence
    }

    fn task_id(&self) -> Option<String> {
        self.context.task_id.clone().map(|task| task.to_string())
    }

    fn admission_view(&self) -> ReactiveAdmissionView {
        ReactiveAdmissionView {
            context: self.context.clone(),
            state_fence: self.state_fence.clone(),
            session_id: String::new(),
            ledger_json: String::new(),
            uri: self.uri.clone(),
            content: self.content.clone(),
            canonical_request_hash: self.operation.canonical_request_hash.clone(),
        }
    }
}

/// Reads back the committed ledger revision for a write response.
async fn read_back_ledger_revision(
    client: &impl CanonicalStoreClient,
    session_id: &str,
    fence: &StateFence,
) -> Result<u64, ReactiveServiceError> {
    let query = reactive_ledger_read_request(session_id.to_owned(), fence.clone())
        .map_err(ReactiveServiceError::from_store)?;
    let payload = client
        .execute_named(query)
        .await
        .map_err(ReactiveServiceError::from_store)?;
    Ok(decode_ledger_read_response(&payload.payload, fence)?.revision)
}

/// Reads back the committed snapshot revision for a write response.
async fn read_back_snapshot_revision(
    client: &impl CanonicalStoreClient,
    uri: &str,
    fence: &StateFence,
) -> Result<u64, ReactiveServiceError> {
    let query = resource_snapshot_read_request(uri.to_owned(), fence.clone())
        .map_err(ReactiveServiceError::from_store)?;
    let payload = client
        .execute_named(query)
        .await
        .map_err(ReactiveServiceError::from_store)?;
    Ok(decode_snapshot_read_response(&payload.payload, fence)?.revision)
}

/// Builds the admitted ledger transition for a request (test-support only).
///
/// Exposes the exact transition the front door hashes and dispatches so
/// integration tests can seal the canonical request hash against the
/// admitted bytes without duplicating admission logic. Unavailable in
/// production builds.
#[cfg(any(test, feature = "test-support"))]
pub fn build_reactive_ledger_transition_for_test(
    request: &ReactiveLedgerRequest,
) -> Result<(PreparedTransition, OperationManifestDigest), ReactiveServiceError> {
    build_ledger_transition(request)
}

/// Builds the admitted snapshot transition for a request (test-support only).
///
/// Same contract as [`build_reactive_ledger_transition_for_test`].
#[cfg(any(test, feature = "test-support"))]
pub fn build_reactive_snapshot_transition_for_test(
    request: &ResourceSnapshotRequest,
) -> Result<(PreparedTransition, OperationManifestDigest, String), ReactiveServiceError> {
    build_snapshot_transition(request)
}

fn decode_ledger_read_response(
    payload: &Value,
    fence: &StateFence,
) -> Result<ReactiveLedgerReadResponse, ReactiveServiceError> {
    let revision = payload.get("revision").and_then(Value::as_u64).ok_or(
        ReactiveServiceError::InvalidField {
            field: "reactive.revision",
            reason: "ledger projection malformed",
        },
    )?;
    let ledger_json = payload
        .get("ledger_json")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(ReactiveLedgerReadResponse {
        ledger_json,
        revision,
        state_fence: fence.clone(),
    })
}

fn decode_snapshot_read_response(
    payload: &Value,
    fence: &StateFence,
) -> Result<ResourceSnapshotReadResponse, ReactiveServiceError> {
    let revision = payload.get("revision").and_then(Value::as_u64).ok_or(
        ReactiveServiceError::InvalidField {
            field: "reactive.revision",
            reason: "snapshot projection malformed",
        },
    )?;
    let encoded = payload.get("content_base64").and_then(Value::as_str);
    let sha = payload
        .get("content_sha256")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let content = match (encoded, &sha) {
        (Some(encoded), Some(sha)) => Some(
            eliot_store_api::decode_resource_content(encoded, sha)
                .map_err(ReactiveServiceError::from_store)?,
        ),
        _ => None,
    };
    if content.is_some() != sha.is_some() {
        return Err(ReactiveServiceError::InvalidField {
            field: "reactive.content",
            reason: "snapshot projection half-present",
        });
    }
    Ok(ResourceSnapshotReadResponse {
        content,
        content_sha256: sha,
        revision,
        state_fence: fence.clone(),
    })
}
