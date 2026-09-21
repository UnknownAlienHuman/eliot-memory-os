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
//! Non-upsert legs address the canonical `notification_id`; the backend
//! resolves it against the store-owned dedup index. The front door never
//! accepts a caller-supplied dedup key on those legs, so identity
//! substitution is impossible here by construction.

use std::collections::BTreeMap;

use eliot_contracts::{EpochId, ResourceGeneration, StateFence};
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, EffectClass, EventProjectionRelationIntents,
    NamedMutationRequest, NotificationRecord, NotificationStateMutation,
    NotificationStateReadRequest, NotificationStateReadResponse, NotificationStateRequest,
    NotificationStateResponse, OperationId, OperationManifestDigest, OrderingScopeId,
    PreparedTransition, ReceiptEnvelope, ScopeId, SecurityContext, StoreError, TransitionClass,
    WriteReceiptStatus, canonical_json_bytes, canonical_request_hash,
    decode_notification_page, generated_operation_manifests, notification_mutation_request,
    notification_read_request, operation_manifest_set_digest, sha256_hex,
    verify_canonical_request_hash,
};
use eliot_store_api::{
    NOTIFY_MUTATION_ACKNOWLEDGE, NOTIFY_MUTATION_DELIVERY, NOTIFY_MUTATION_RESOLVE,
    NOTIFY_MUTATION_UPSERT, NOTIFY_PARAM_AUTHORIZATION_JSON, NOTIFY_PARAM_CHANNEL,
    NOTIFY_PARAM_DEDUP_KEY, NOTIFY_PARAM_DELIVERY_JSON, NOTIFY_PARAM_DISPOSITION,
    NOTIFY_PARAM_MUTATION, NOTIFY_PARAM_NOTIFICATION_ID, NOTIFY_PARAM_PRINCIPAL,
    NOTIFY_PARAM_RECORD_JSON, NOTIFY_PARAM_SOURCE_RECEIPT_JSON, NOTIFICATION_STATE_SCOPE,
    NotificationContractError,
};
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
    pub fn bind(
        service: &KernelService,
        principal_ref: &str,
    ) -> Result<Self, KernelServiceError> {
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

/// Front-door errors for notification-state admission.
#[derive(Clone, Debug, Error, PartialEq)]
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
                if field == "notification.dedup_key"
                    && reason == "unknown notification" =>
            {
                Self::UnknownNotification
            }
            StoreError::InvalidField { field, reason }
                if field == "notification.notification_id"
                    && reason == "unknown notification" =>
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
    request.validate().map_err(contract_field_error)?;
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
            .envelope
            .clone()
            .ok_or(NotificationServiceError::MissingReceiptEnvelope)?;
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
        .envelope
        .clone()
        .ok_or(NotificationServiceError::MissingReceiptEnvelope)?;
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
    request
        .validate()
        .map_err(|_| NotificationServiceError::InvalidField {
            field: "notification.read",
            reason: "notification read request failed closed validation",
        })?;
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
    let page =
        eliot_store_api::decode_notification_page(&payload).map_err(NotificationServiceError::from_store)?;
    if page.state_fence != request.state_fence {
        return Err(NotificationServiceError::FenceMismatch);
    }
    Ok(page)
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
            receipt
                .envelope
                .clone()
                .ok_or(NotificationServiceError::MissingReceiptEnvelope)
                .map(Some)
        }
        Some(_) => Err(NotificationServiceError::IdentityConflict),
        None => Ok(None),
    }
}

fn contract_field_error(error: NotificationContractError) -> NotificationServiceError {
    match error {
        NotificationContractError::InvalidField { field, .. } => {
            NotificationServiceError::InvalidField {
                field,
                reason: "notification request failed closed validation",
            }
        }
        NotificationContractError::UnknownMutation => NotificationServiceError::InvalidField {
            field: "notification.mutation",
            reason: "unknown notification mutation leg",
        },
        NotificationContractError::MissingParameter(name) => {
            NotificationServiceError::InvalidField {
                field: name,
                reason: "missing required notification parameter",
            }
        }
    }
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
) -> Result<(PreparedTransition, eliot_store_api::OperationManifestDigest), NotificationServiceError>
{
    let parameters = notification_parameters(request)?;
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests()?).map_err(|_| {
            NotificationServiceError::ManifestMismatch
        })?;
    let admission_digest = sha256_hex(
        &canonical_json_bytes(request)
            .map_err(|_| NotificationServiceError::DigestMismatch)?,
    );
    let scope = ScopeId::new(eliot_store_api::NOTIFICATION_STATE_SCOPE).map_err(|_| {
        NotificationServiceError::InvalidField {
            field: "notification.scope",
            reason: "notification scope identity is invalid",
        }
    })?;
    let ordering = OrderingScopeId::new(eliot_store_api::NOTIFICATION_STATE_SCOPE).map_err(|_| {
        NotificationServiceError::InvalidField {
            field: "notification.scope",
            reason: "notification ordering scope identity is invalid",
        }
    })?;
    let transition = PreparedTransition {
        identity: request.operation.clone(),
        state_fence: request.state_fence.clone(),
        scope_id: scope,
        task_id: request
            .context
            .task_id
            .clone()
            .map(|task| task.to_string()),
        ordering_scopes: vec![ordering],
        transition_class: TransitionClass::NotificationState,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: admission_digest,
        operation_manifest_digest: manifest_digest.clone(),
        named_operations: vec![notification_mutation_request(parameters)],
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
        .map_err(NotificationServiceError::from_store)?;
    Ok((transition, manifest_digest))
}

fn notification_parameters(
    request: &NotificationStateRequest,
) -> Result<BTreeMap<String, Value>, NotificationServiceError> {
    use eliot_store_api::NotificationStateMutation;

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
            attempt,
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
                Value::String(channel_wire(channel).to_owned()),
            );
            parameters.insert(
                NOTIFY_PARAM_DELIVERY_JSON.to_owned(),
                serde_json::to_value(&attempt.state)
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
) -> Result<NotificationRecord, NotificationServiceError> {
    use eliot_store_api::NotificationStateMutation;

    let (dedup_key, notification_id) = match &request.mutation {
        NotificationStateMutation::Upsert { record, .. } => {
            (Some(record.dedup_key.clone()), None)
        }
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
    let page =
        decode_notification_page(&payload).map_err(NotificationServiceError::from_store)?;
    if page.state_fence != *fence {
        return Err(NotificationServiceError::FenceMismatch);
    }
    page
        .records
        .into_iter()
        .next()
        .ok_or(NotificationServiceError::UnknownNotification)
}

/// Closed channel wire spelling shared with the store contract validator.
fn channel_wire(channel: &eliot_store_api::DeliveryChannel) -> &'static str {
    match channel {
        eliot_store_api::DeliveryChannel::ControlBoard => "CONTROL_BOARD",
        eliot_store_api::DeliveryChannel::NativeToast => "NATIVE_TOAST",
        eliot_store_api::DeliveryChannel::WindowsEventLog => "WINDOWS_EVENT_LOG",
        eliot_store_api::DeliveryChannel::RecoveryFallback => "RECOVERY_FALLBACK",
    }
}
