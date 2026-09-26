//! Authenticated Kernel front-door handler for canonical notification state
//! (issue #1780, I11.5/I11.7).
//!
//! This module is the authority/fence/operation boundary for notification
//! writes and reads: it binds an authenticated session from live Kernel
//! state, validates the protected request (identity, fence, operation
//! identity, canonical request hash, receipt bindings), dispatches exactly
//! once through the existing [`CanonicalStoreClient`] path, validates the
//! exact store response receipt, and maps unsupported/unavailable/unknown
//! outcomes without claiming success. Semantic record state lives in the
//! canonical store; this service never invents delivery or resolution.
//!
//! Record, transition, and resolution-authority types are the shared
//! kernel-core model (`eliot_kernel_core::notification_state`), consumed
//! directly — never redefined. Non-upsert legs address the canonical
//! `notification_id`; the backend resolves it against the store-owned dedup
//! index. The front door never accepts a caller-supplied dedup key on those
//! legs, so identity substitution is impossible here by construction.

use std::collections::BTreeMap;

use eliot_contracts::{EpochId, ResourceGeneration, StateFence};
use eliot_kernel_core::{
    DeliveryChannel, DeliveryState, Notification, NotificationDraft, ResolutionAuthorization,
};
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, EffectClass, EventProjectionRelationIntents,
    NOTIFICATION_STATE_SCOPE, NOTIFY_MUTATION_ACKNOWLEDGE, NOTIFY_MUTATION_DELIVERY,
    NOTIFY_MUTATION_RESOLVE, NOTIFY_MUTATION_UPSERT, NOTIFY_PARAM_AUTHORIZATION_JSON,
    NOTIFY_PARAM_CHANNEL, NOTIFY_PARAM_DEDUP_KEY, NOTIFY_PARAM_DELIVERY_JSON,
    NOTIFY_PARAM_DISPOSITION, NOTIFY_PARAM_MUTATION, NOTIFY_PARAM_NOTIFICATION_ID,
    NOTIFY_PARAM_PRINCIPAL, NOTIFY_PARAM_RECORD_JSON, NOTIFY_PARAM_SOURCE_RECEIPT_JSON,
    OperationId, OperationIdentity, OperationManifestDigest, OrderingScopeId, PreparedTransition,
    ReceiptEnvelope, RequestMetadata, ScopeId, SecurityContext, StoreError, TransitionClass,
    WriteReceiptStatus, canonical_json_bytes, generated_operation_manifests,
    notification_mutation_request, notification_read_request, operation_manifest_set_digest,
    sha256_hex, verify_canonical_request_hash,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{KernelService, KernelServiceError, KernelServiceState, validate_text};

/// Authenticated notification session bound from live Kernel state.
#[derive(Clone, Debug)]
pub struct AuthenticatedNotificationSession {
    principal: String,
    authority_epoch: EpochId,
    generation: u64,
}

impl AuthenticatedNotificationSession {
    /// Binds one notification session from live Kernel state.
    ///
    /// Fails closed when the generation is fenced, the service is not
    /// `Ready`, no candidate lineage or consumed activation receipt exists,
    /// the activation no longer agrees with the live epoch (revoked/stale
    /// activation), or the principal reference is not bounded wire text.
    pub fn bind(service: &KernelService, principal_ref: &str) -> Result<Self, KernelServiceError> {
        validate_text(principal_ref, "notification.principal")?;
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
                field: "notification.authority_epoch",
            });
        }
        if !activation.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "notification.authority_epoch",
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

    /// Returns the authority epoch bound at session time.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the activation generation bound at session time.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Re-validates the session against live service authority.
    ///
    /// A session bound before an epoch advance, a generation cutover, a
    /// fence, or a drain is stale and fails here — before any admission
    /// input — so a replayed session can never smuggle old authority into a
    /// new epoch.
    fn live_authority(
        &self,
        service: &KernelService,
    ) -> Result<(EpochId, u64), KernelServiceError> {
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
                field: "notification.authority_epoch",
            });
        }
        let live_generation = activation.generation.value();
        if !self.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "notification.authority_epoch",
            });
        }
        if self.generation != live_generation {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "notification.generation",
            });
        }
        Ok((live_epoch, live_generation))
    }

    /// Builds the live service context; the presented fence must agree with it.
    pub fn service_context(
        &self,
        service: &KernelService,
    ) -> Result<NotificationServiceContext, KernelServiceError> {
        let (authority_epoch, generation) = self.live_authority(service)?;
        Ok(NotificationServiceContext {
            authority_epoch,
            generation,
        })
    }
}

/// Live service authority a notification request is admitted under.
#[derive(Clone, Debug)]
pub struct NotificationServiceContext {
    /// Live authority epoch.
    pub authority_epoch: EpochId,
    /// Live activation generation.
    pub generation: u64,
}

/// Closed notification-state mutation legs on shared model types.
///
/// The upsert leg boxes its two large payloads (`NotificationDraft`,
/// `ReceiptEnvelope`) so the enum stays flat across legs; all other legs
/// carry small identity/disposition values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum NotificationStateMutation {
    /// Create or coalesce exactly one record before any delivery attempt.
    Upsert {
        /// Caller canonical fields.
        record: Box<NotificationDraft>,
        /// Admission/provenance receipt for the upsert.
        source_receipt: Box<ReceiptEnvelope>,
    },
    /// Record the verified latest delivery state without resolving the item.
    Delivery {
        /// Canonical notification identity.
        notification_id: String,
        /// Channel the attempt used.
        channel: DeliveryChannel,
        /// Verified delivery outcome.
        delivery: DeliveryState,
    },
    /// Suppress repeated toast selection; never resolves the record.
    Acknowledge {
        /// Canonical notification identity.
        notification_id: String,
        /// Acknowledging principal.
        principal: String,
    },
    /// Resolve only with a protected, evidence-bound authority receipt.
    Resolve {
        /// Canonical notification identity.
        notification_id: String,
        /// Human disposition recorded by the owner.
        disposition: String,
        /// Protected receipt/evidence authorization.
        authorization: Box<ResolutionAuthorization>,
    },
}

/// Authenticated notification-state write request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotificationStateRequest {
    /// Exact operation identity (idempotency + canonical request hash).
    pub operation: OperationIdentity,
    /// Caller request metadata bound by the Kernel route.
    pub context: RequestMetadata,
    /// Fence the mutation is admitted under.
    pub state_fence: StateFence,
    /// Closed mutation leg.
    pub mutation: NotificationStateMutation,
}

/// Notification-state write response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotificationStateResponse {
    /// Current canonical record after the mutation.
    pub record: Notification,
    /// Exact store response receipt (never fabricated by the caller).
    pub receipt: ReceiptEnvelope,
    /// True when the response replays an already-admitted operation identity.
    pub replayed: bool,
}

/// Same-fence canonical read request for the `ControlBoard` projection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotificationStateReadRequest {
    /// Caller request metadata bound by the Kernel route.
    pub context: RequestMetadata,
    /// Fence the projection is admitted under.
    pub state_fence: StateFence,
    /// Optional record-scope filter (never a quiet-hours filter).
    pub scope: Option<String>,
    /// Whether resolved rows are included.
    pub include_resolved: bool,
    /// Page-size bound.
    pub page_limit: u16,
    /// Opaque dedup-key cursor for paging.
    pub cursor: Option<String>,
}

/// Canonical inbox metrics preserved by the read projection.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationMetrics {
    /// Unresolved records in the projected set.
    pub unresolved_total: u64,
    /// Unresolved critical records.
    pub critical_unresolved: u64,
    /// Unresolved action-required records.
    pub action_required_unresolved: u64,
    /// Unresolved records with failed/uncertain delivery.
    pub failed_delivery_unresolved: u64,
    /// Unresolved acknowledged records (still visible).
    pub acknowledged_unresolved: u64,
    /// Resolved records in the projected set.
    pub resolved_total: u64,
}

/// Same-fence canonical read response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NotificationStateReadResponse {
    /// Projected records in deterministic dedup-key order.
    pub records: Vec<Notification>,
    /// Inbox metrics over the projected set.
    pub metrics: NotificationMetrics,
    /// Fence the projection was admitted under.
    pub state_fence: StateFence,
    /// Owner revision the projection was read at.
    pub revision: u64,
}

/// Front-door errors for notification-state admission.
#[derive(Debug, Error)]
pub enum NotificationServiceError {
    /// A field failed bounded identity validation.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason code.
        reason: &'static str,
    },
    /// The presented fence does not match live service authority.
    #[error("notification state fence mismatch")]
    FenceMismatch,
    /// The operation identity collides with different executable bytes.
    #[error("notification operation identity conflict")]
    IdentityConflict,
    /// The canonical request hash does not match the admitted bytes.
    #[error("notification canonical request digest mismatch")]
    DigestMismatch,
    /// The store refused to commit the admitted transition.
    #[error("notification transition was not committed")]
    NotCommitted,
    /// The store manifest digest does not match the admitted catalogue.
    #[error("notification operation manifest mismatch")]
    ManifestMismatch,
    /// The addressed record does not exist.
    #[error("unknown notification")]
    UnknownNotification,
    /// The addressed record is already resolved.
    #[error("notification is already resolved")]
    AlreadyResolved,
    /// The store committed no response receipt; the outcome is unknown.
    #[error("notification response receipt is missing; outcome is unknown")]
    MissingReceiptEnvelope,
    /// The backend rejected the mutation.
    #[error("notification rejected: {0}")]
    Rejected(String),
    /// A closed store error.
    #[error("notification store: {0}")]
    Store(#[from] StoreError),
    /// A Kernel service error.
    #[error("notification service: {0}")]
    Service(#[from] KernelServiceError),
}

impl NotificationServiceError {
    /// Projects a closed store error onto the front-door set, preserving the
    /// fail-closed variants the acceptance proofs discriminate.
    #[must_use]
    pub fn from_store(error: StoreError) -> Self {
        match error {
            StoreError::FenceMismatch => Self::FenceMismatch,
            StoreError::IdentityConflict => Self::IdentityConflict,
            StoreError::InvalidField { field, reason }
                if field == "notification.notification_id" && reason == "unknown notification" =>
            {
                Self::UnknownNotification
            }
            StoreError::InvalidField { field, reason }
                if field == "notification.resolution" && reason == "record is already resolved" =>
            {
                Self::AlreadyResolved
            }
            other => Self::Store(other),
        }
    }
}

/// Handles one authenticated notification-state write.
///
/// Flow: live session revalidation → request shape validation → live fence
/// agreement → canonical-hash verification → exact-identity reconcile (a
/// stored receipt with the same identity and bytes replays without a second
/// mutation; changed bytes conflict) → single `apply_prepared` dispatch →
/// exact response-receipt validation → same-fence record read-back. Unknown,
/// unavailable, and uncommitted outcomes never report success.
pub async fn handle_notification_state_request(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedNotificationSession,
    request: &NotificationStateRequest,
) -> Result<NotificationStateResponse, NotificationServiceError> {
    let context = session
        .service_context(service)
        .map_err(NotificationServiceError::Service)?;
    validate_notification_request(request)?;
    require_live_fence(&context, &request.state_fence)?;
    if request.context.state_fence != request.state_fence {
        return Err(NotificationServiceError::FenceMismatch);
    }
    let meta = &request.context;
    let (transition, manifest_digest) = build_notification_transition(request)?;
    let view = CanonicalRequestView::from_apply(meta, &transition, &[], &[]);
    verify_canonical_request_hash(&view, &request.operation.canonical_request_hash)
        .map_err(|_| NotificationServiceError::DigestMismatch)?;
    if let Some(existing) = client
        .receipt(request.operation.operation_id.clone())
        .await
        .map_err(NotificationServiceError::from_store)?
    {
        if existing.canonical_request_hash != request.operation.canonical_request_hash
            || existing.idempotency_key != request.operation.idempotency_key
        {
            return Err(NotificationServiceError::IdentityConflict);
        }
        let record = read_back_notification(client, request, &request.state_fence).await?;
        let receipt = existing
            .require_reconciliation_envelope()
            .map_err(NotificationServiceError::from_store)?
            .clone();
        return Ok(NotificationStateResponse {
            record,
            receipt,
            replayed: true,
        });
    }
    let receipt = client
        .apply_prepared(meta, transition, Vec::new(), Vec::new())
        .await
        .map_err(NotificationServiceError::from_store)?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(NotificationServiceError::NotCommitted);
    }
    receipt
        .validate()
        .map_err(NotificationServiceError::from_store)?;
    if receipt.state_fence != request.state_fence {
        return Err(NotificationServiceError::FenceMismatch);
    }
    if receipt.operation_manifest_digest != manifest_digest {
        return Err(NotificationServiceError::ManifestMismatch);
    }
    let envelope = receipt
        .require_reconciliation_envelope()
        .map_err(NotificationServiceError::from_store)?
        .clone();
    envelope
        .validate()
        .map_err(|_| NotificationServiceError::MissingReceiptEnvelope)?;
    let record = read_back_notification(client, request, &request.state_fence).await?;
    Ok(NotificationStateResponse {
        record,
        receipt: envelope,
        replayed: false,
    })
}

/// Handles one authenticated notification-state read.
///
/// Same-fence canonical projection only. Unresolved acknowledged records,
/// unresolved failed-delivery records, and unresolved critical and
/// action-required records are preserved by the backend projection; quiet
/// hours never filter this read.
pub async fn handle_notification_state_read(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedNotificationSession,
    request: &NotificationStateReadRequest,
) -> Result<NotificationStateReadResponse, NotificationServiceError> {
    let context = session
        .service_context(service)
        .map_err(NotificationServiceError::Service)?;
    validate_notification_read_request(request)?;
    require_live_fence(&context, &request.state_fence)?;
    if request.context.state_fence != request.state_fence {
        return Err(NotificationServiceError::FenceMismatch);
    }
    let query = notification_read_request(
        request.scope.clone(),
        None,
        None,
        request.include_resolved,
        request.page_limit,
        request.cursor.clone(),
        request.state_fence.clone(),
    )
    .map_err(NotificationServiceError::from_store)?;
    let payload = client
        .execute_named(query)
        .await
        .map_err(NotificationServiceError::from_store)?;
    decode_notification_read_response(&payload.payload, &request.state_fence)
}

/// Reconciles one exact admitted operation identity after transport loss.
///
/// Returns the stored receipt when the backend holds it; otherwise reports
/// the unknown outcome without retrying under a fresh identity and without
/// inferring success from the timeout.
pub async fn reconcile_notification_state(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedNotificationSession,
    operation_id: OperationId,
    idempotency_key: &str,
    canonical_request_hash: &str,
) -> Result<Option<ReceiptEnvelope>, NotificationServiceError> {
    let _context = session
        .service_context(service)
        .map_err(NotificationServiceError::Service)?;
    validate_text(idempotency_key, "notification.idempotency_key")?;
    validate_text(
        canonical_request_hash,
        "notification.canonical_request_hash",
    )?;
    let stored = client
        .receipt(operation_id)
        .await
        .map_err(NotificationServiceError::from_store)?;
    match stored {
        Some(receipt)
            if receipt.idempotency_key == idempotency_key
                && receipt.canonical_request_hash == canonical_request_hash =>
        {
            let envelope = receipt
                .require_reconciliation_envelope()
                .map_err(NotificationServiceError::from_store)?
                .clone();
            Ok(Some(envelope))
        }
        Some(_) => Err(NotificationServiceError::IdentityConflict),
        None => Ok(None),
    }
}

fn validate_notification_request(
    request: &NotificationStateRequest,
) -> Result<(), NotificationServiceError> {
    let invalid = |field: &'static str| NotificationServiceError::InvalidField {
        field,
        reason: "notification request failed closed validation",
    };
    request
        .operation
        .validate()
        .map_err(|_| invalid("notification.operation"))?;
    match &request.mutation {
        NotificationStateMutation::Upsert {
            record,
            source_receipt,
        } => {
            record
                .validate()
                .map_err(|_| invalid("notification.record"))?;
            if record.state_fence != request.state_fence {
                return Err(invalid("notification.state_fence"));
            }
            source_receipt
                .validate()
                .map_err(|_| invalid("notification.source_receipt"))?;
        }
        NotificationStateMutation::Delivery { delivery, .. } => {
            delivery
                .validate()
                .map_err(|_| invalid("notification.delivery"))?;
        }
        NotificationStateMutation::Acknowledge { principal, .. } => {
            validate_text(principal, "notification.principal")
                .map_err(|_| invalid("notification.principal"))?;
        }
        NotificationStateMutation::Resolve {
            disposition,
            authorization,
            ..
        } => {
            validate_text(disposition, "notification.disposition")
                .map_err(|_| invalid("notification.disposition"))?;
            if authorization.evidence_handles.is_empty() {
                return Err(invalid("notification.evidence_handles"));
            }
        }
    }
    Ok(())
}

fn validate_notification_read_request(
    request: &NotificationStateReadRequest,
) -> Result<(), NotificationServiceError> {
    let invalid = |field: &'static str| NotificationServiceError::InvalidField {
        field,
        reason: "notification read request failed closed validation",
    };
    if let Some(scope) = &request.scope {
        validate_text(scope, "notification.scope")?;
    }
    if request.page_limit == 0 || request.page_limit > eliot_store_api::MAX_NOTIFICATION_PAGE_LIMIT
    {
        return Err(invalid("notification.page_limit"));
    }
    if let Some(cursor) = &request.cursor {
        validate_text(cursor, "notification.cursor")?;
    }
    Ok(())
}

fn require_live_fence(
    context: &NotificationServiceContext,
    fence: &StateFence,
) -> Result<(), NotificationServiceError> {
    if !fence
        .authority_epoch
        .is_same_authority(&context.authority_epoch)
    {
        return Err(NotificationServiceError::FenceMismatch);
    }
    let generation = ResourceGeneration::new(context.generation).map_err(|_| {
        NotificationServiceError::InvalidField {
            field: "notification.generation",
            reason: "live generation is not a valid resource generation",
        }
    })?;
    if fence.resource_generation != generation {
        return Err(NotificationServiceError::FenceMismatch);
    }
    fence
        .validate()
        .map_err(|_| NotificationServiceError::FenceMismatch)?;
    Ok(())
}

fn build_notification_transition(
    request: &NotificationStateRequest,
) -> Result<(PreparedTransition, OperationManifestDigest), NotificationServiceError> {
    let parameters = notification_parameters(request)?;
    let manifest_digest = operation_manifest_set_digest(&generated_operation_manifests()?)
        .map_err(|_| NotificationServiceError::ManifestMismatch)?;
    // The admission digest binds the admitted request with the identity-hash
    // field cleared: the hash itself is bound separately by the transition
    // view, so clearing keeps admission deterministic across sealing (which
    // fills the hash after building) and dispatch (which rebuilds from the
    // sealed request). A caller-supplied admission digest is never trusted.
    let mut admission_view = request.clone();
    admission_view.operation.canonical_request_hash = String::new();
    let admission_digest = sha256_hex(
        &canonical_json_bytes(&admission_view)
            .map_err(|_| NotificationServiceError::DigestMismatch)?,
    );
    let scope = ScopeId::new(NOTIFICATION_STATE_SCOPE).map_err(|_| {
        NotificationServiceError::InvalidField {
            field: "notification.scope",
            reason: "notification scope identity is invalid",
        }
    })?;
    let ordering = OrderingScopeId::new(NOTIFICATION_STATE_SCOPE).map_err(|_| {
        NotificationServiceError::InvalidField {
            field: "notification.scope",
            reason: "notification ordering scope identity is invalid",
        }
    })?;
    let mut transition = PreparedTransition {
        identity: request.operation.clone(),
        state_fence: request.state_fence.clone(),
        scope_id: scope,
        task_id: request.context.task_id.clone().map(|task| task.to_string()),
        ordering_scopes: vec![ordering],
        transition_class: TransitionClass::NotificationState,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: admission_digest,
        semantic_source_revisions: Vec::new(),
        admission_digest: String::new(),
        operation_manifest_digest: manifest_digest.clone(),
        mutation_plan_digest: String::new(),
        named_operations: vec![notification_mutation_request(parameters)],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    // Issue #18: notification writes dispatch with no expected revision
    // heads, so no source revisions are bound; the plan and admission
    // digests still derive from the exact admitted transition.
    eliot_store_api::bind_issue18_digests(&mut transition, Vec::new())
        .map_err(NotificationServiceError::from_store)?;
    transition
        .validate()
        .map_err(NotificationServiceError::from_store)?;
    Ok((transition, manifest_digest))
}

/// Builds the admitted transition for a request (test-support only).
///
/// Exposes the exact transition the front door hashes and dispatches so
/// integration tests can seal the canonical request hash against the
/// admitted bytes without duplicating admission logic. Unavailable in
/// production builds.
#[cfg(any(test, feature = "test-support"))]
pub fn build_notification_transition_for_test(
    request: &NotificationStateRequest,
) -> Result<(PreparedTransition, OperationManifestDigest), NotificationServiceError> {
    build_notification_transition(request)
}

fn notification_parameters(
    request: &NotificationStateRequest,
) -> Result<BTreeMap<String, Value>, NotificationServiceError> {
    let invalid = |field: &'static str| NotificationServiceError::InvalidField {
        field,
        reason: "notification mutation failed closed validation",
    };
    let mut parameters = BTreeMap::new();
    match &request.mutation {
        NotificationStateMutation::Upsert {
            record,
            source_receipt,
        } => {
            parameters.insert(
                NOTIFY_PARAM_MUTATION.to_owned(),
                Value::String(NOTIFY_MUTATION_UPSERT.to_owned()),
            );
            parameters.insert(
                NOTIFY_PARAM_DEDUP_KEY.to_owned(),
                Value::String(record.dedup_key.clone()),
            );
            parameters.insert(
                NOTIFY_PARAM_RECORD_JSON.to_owned(),
                serde_json::to_value(record).map_err(|_| invalid("notification.record_json"))?,
            );
            parameters.insert(
                NOTIFY_PARAM_SOURCE_RECEIPT_JSON.to_owned(),
                serde_json::to_value(source_receipt)
                    .map_err(|_| invalid("notification.source_receipt_json"))?,
            );
        }
        NotificationStateMutation::Delivery {
            notification_id,
            channel,
            delivery,
        } => {
            parameters.insert(
                NOTIFY_PARAM_MUTATION.to_owned(),
                Value::String(NOTIFY_MUTATION_DELIVERY.to_owned()),
            );
            parameters.insert(
                NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
                Value::String(notification_id.clone()),
            );
            parameters.insert(
                NOTIFY_PARAM_CHANNEL.to_owned(),
                Value::String(channel_wire(*channel).to_owned()),
            );
            parameters.insert(
                NOTIFY_PARAM_DELIVERY_JSON.to_owned(),
                serde_json::to_value(delivery)
                    .map_err(|_| invalid("notification.delivery_json"))?,
            );
        }
        NotificationStateMutation::Acknowledge {
            notification_id,
            principal,
        } => {
            parameters.insert(
                NOTIFY_PARAM_MUTATION.to_owned(),
                Value::String(NOTIFY_MUTATION_ACKNOWLEDGE.to_owned()),
            );
            parameters.insert(
                NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
                Value::String(notification_id.clone()),
            );
            parameters.insert(
                NOTIFY_PARAM_PRINCIPAL.to_owned(),
                Value::String(principal.clone()),
            );
        }
        NotificationStateMutation::Resolve {
            notification_id,
            disposition,
            authorization,
        } => {
            parameters.insert(
                NOTIFY_PARAM_MUTATION.to_owned(),
                Value::String(NOTIFY_MUTATION_RESOLVE.to_owned()),
            );
            parameters.insert(
                NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
                Value::String(notification_id.clone()),
            );
            parameters.insert(
                NOTIFY_PARAM_DISPOSITION.to_owned(),
                Value::String(disposition.clone()),
            );
            parameters.insert(
                NOTIFY_PARAM_AUTHORIZATION_JSON.to_owned(),
                serde_json::to_value(authorization)
                    .map_err(|_| invalid("notification.authorization_json"))?,
            );
        }
    }
    Ok(parameters)
}

async fn read_back_notification(
    client: &impl CanonicalStoreClient,
    request: &NotificationStateRequest,
    fence: &StateFence,
) -> Result<Notification, NotificationServiceError> {
    let (dedup_key, notification_id) = match &request.mutation {
        NotificationStateMutation::Upsert { record, .. } => (Some(record.dedup_key.clone()), None),
        NotificationStateMutation::Delivery {
            notification_id, ..
        }
        | NotificationStateMutation::Acknowledge {
            notification_id, ..
        }
        | NotificationStateMutation::Resolve {
            notification_id, ..
        } => (None, Some(notification_id.clone())),
    };
    let query = notification_read_request(
        None,
        dedup_key,
        notification_id,
        true,
        1,
        None,
        fence.clone(),
    )
    .map_err(NotificationServiceError::from_store)?;
    let payload = client
        .execute_named(query)
        .await
        .map_err(NotificationServiceError::from_store)?;
    let page = decode_notification_read_response(&payload.payload, fence)?;
    page.records
        .into_iter()
        .next()
        .ok_or(NotificationServiceError::UnknownNotification)
}

/// Decodes a backend read payload into the typed read response.
///
/// The backend emits exactly the `records` / `metrics` / `state_fence` /
/// `revision` shape; unknown or misfenced payloads fail closed here.
fn decode_notification_read_response(
    payload: &Value,
    fence: &StateFence,
) -> Result<NotificationStateReadResponse, NotificationServiceError> {
    let records = payload.get("records").and_then(Value::as_array).ok_or(
        NotificationServiceError::InvalidField {
            field: "notification.records",
            reason: "read payload must carry records",
        },
    )?;
    let mut decoded = Vec::with_capacity(records.len());
    for value in records {
        let record: Notification = serde_json::from_value(value.clone()).map_err(|_| {
            NotificationServiceError::InvalidField {
                field: "notification.records",
                reason: "record payload is not a canonical notification",
            }
        })?;
        if record.state_fence != *fence {
            return Err(NotificationServiceError::FenceMismatch);
        }
        decoded.push(record);
    }
    let metrics: NotificationMetrics =
        serde_json::from_value(payload.get("metrics").cloned().ok_or(
            NotificationServiceError::InvalidField {
                field: "notification.metrics",
                reason: "read payload must carry metrics",
            },
        )?)
        .map_err(|_| NotificationServiceError::InvalidField {
            field: "notification.metrics",
            reason: "metrics payload is not canonical",
        })?;
    let state_fence: StateFence = serde_json::from_value(
        payload
            .get("state_fence")
            .cloned()
            .ok_or(NotificationServiceError::FenceMismatch)?,
    )
    .map_err(|_| NotificationServiceError::FenceMismatch)?;
    if state_fence != *fence {
        return Err(NotificationServiceError::FenceMismatch);
    }
    let revision: u64 = payload.get("revision").and_then(Value::as_u64).ok_or(
        NotificationServiceError::InvalidField {
            field: "notification.revision",
            reason: "read payload must carry revision",
        },
    )?;
    Ok(NotificationStateReadResponse {
        records: decoded,
        metrics,
        state_fence,
        revision,
    })
}

/// Closed channel wire spelling shared with the store contract validator.
fn channel_wire(channel: DeliveryChannel) -> &'static str {
    match channel {
        DeliveryChannel::ControlBoard => "CONTROL_BOARD",
        DeliveryChannel::NativeToast => "NATIVE_TOAST",
        DeliveryChannel::WindowsEventLog => "WINDOWS_EVENT_LOG",
        DeliveryChannel::RecoveryFallback => "RECOVERY_FALLBACK",
    }
}
