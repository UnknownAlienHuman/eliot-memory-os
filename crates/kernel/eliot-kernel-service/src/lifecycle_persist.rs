//! Authenticated Kernel front-door handler persisting verified lifecycle
//! admission chains (issue #1905).
//!
//! This module is the authority/fence/operation boundary for lifecycle
//! persistence: it binds an authenticated session from live Kernel state,
//! re-verifies the presented admission chain through the curation owner
//! (order, shapes, and receipt continuity), persists it as one capture
//! plus one hash-chained audit leg per hop through the existing
//! [`CanonicalStoreClient`] path, validates every store response
//! receipt, and maps outcomes without claiming success. Curation and
//! epistemic semantics stay with their owners: the seam consumes the
//! typed [`CurationAdmission`] chain directly — never a generic
//! parameter map — and never derives epistemic content, lineage, or
//! standing.
//!
//! Persist layout per chain (all values exact, nothing invented):
//!
//! ```text
//! T0 = [CaptureObservation { subject: genesis output handle }]
//! Ti+1 = [AppendAuditEvent {
//!     operation_id: own transition id (== receipt preset audit event),
//!     idempotency_key: own key,
//!     session_id: bound session,
//!     access_digest: hop curation receipt digest,
//!     action_digest: previous committed transition hash,
//!     expected_revision: 1-based hop position,
//! }]
//! ```
//!
//! Each transition carries `event_ids = [curation receipt id]`, so the
//! committed `WriteReceipt.emitted_event_ids` bind back to the admission
//! through the returned [`LinkAuditBinding`]; the curation side links
//! with its own `link_audit` (digest already covers the preset event).
//! Revision hops carry no mutation leg of their own: an
//! `EpistemicRevisionPayload` cannot be constructed from curation data
//! without fabricating epistemic standing, so revision content stays in
//! the curation receipt while the store holds the immutable raw input
//! plus the ordered audit linkage. Resuming an interrupted chain
//! re-issues the same request: sealed hops replay without remutation.

use eliot_contracts::ArtifactId;
use eliot_contracts::SessionId;
use eliot_memory_curation::admission::{
    CurationAdmission, CurationMutationOperation, verify_admission_chain,
};
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, EffectClass, EventId,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationIdentity, OrderingScopeId, PreparedTransition, ReceiptEnvelope, RequestMetadata,
    ScopeId, SecurityContext, StateFence, StoreError, TransitionClass, canonical_json_bytes,
    generated_operation_manifests, operation_manifest_set_digest, sha256_hex,
    verify_canonical_request_hash,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{KernelService, KernelServiceError, KernelServiceState, validate_text};

/// Authenticated lifecycle session bound from live Kernel state.
#[derive(Clone, Debug)]
pub struct AuthenticatedLifecycleSession {
    principal: String,
    authority_epoch: eliot_contracts::EpochId,
    generation: u64,
}

impl AuthenticatedLifecycleSession {
    /// Binds one lifecycle session from live Kernel state.
    ///
    /// Fails closed when the generation is fenced, the service is not
    /// `Ready`, no candidate lineage or consumed activation receipt exists,
    /// the activation no longer agrees with the live epoch (revoked/stale
    /// activation), or the principal reference is not bounded wire text.
    pub fn bind(service: &KernelService, principal_ref: &str) -> Result<Self, KernelServiceError> {
        validate_text(principal_ref, "lifecycle.persist.principal")?;
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
                field: "lifecycle.persist.authority_epoch",
            });
        }
        if !activation.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "lifecycle.persist.authority_epoch",
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
    ) -> Result<LifecycleServiceContext, KernelServiceError> {
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
                field: "lifecycle.persist.authority_epoch",
            });
        }
        if !self.authority_epoch.is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "lifecycle.persist.authority_epoch",
            });
        }
        if self.generation != activation.generation.value() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "lifecycle.persist.generation",
            });
        }
        Ok(LifecycleServiceContext {
            authority_epoch: live_epoch,
            generation: activation.generation.value(),
        })
    }
}

/// Live service authority a persist request is admitted under.
#[derive(Clone, Debug)]
pub struct LifecycleServiceContext {
    /// Live authority epoch.
    pub authority_epoch: eliot_contracts::EpochId,
    /// Live activation generation.
    pub generation: u64,
}

/// Authenticated persist request for one verified admission chain.
#[derive(Clone, Debug, Serialize)]
pub struct LifecyclePersistRequest {
    /// Caller request metadata bound by the Kernel route.
    pub context: RequestMetadata,
    /// Fence every hop is admitted under (single-fence calls only).
    pub state_fence: StateFence,
    /// Ordered verified admissions, genesis-first.
    pub chain: Vec<CurationAdmission>,
    /// Caller-issued transition identities: exactly `chain.len() + 1`
    /// (capture plus one audit leg per hop, in order).
    pub hop_identities: Vec<OperationIdentity>,
}

/// One persisted hop: the committed audit leg plus its linkage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PersistedHop {
    /// Curation receipt identity this hop persists.
    pub curation_receipt_id: String,
    /// Committed audit transition operation identity.
    pub operation_id: OperationIdentity,
    /// Exact store response receipt (never fabricated by the caller).
    pub receipt: ReceiptEnvelope,
    /// Emitted event ids bound back to the admission.
    pub emitted_event_ids: Vec<String>,
    /// True when the hop replayed an already-admitted identity.
    pub replayed: bool,
}

/// Audit linkage binding one admission to its committed audit leg.
///
/// The curation side completes the loop with its own `link_audit`
/// (the preset event id already sits inside the receipt digest, so no
/// digest changes when this binding is recorded).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LinkAuditBinding {
    /// Curation receipt identity linked by this binding.
    pub curation_receipt_id: String,
    /// Committed audit transition operation identity.
    pub audit_operation_id: String,
    /// Emitted event ids bound back to the admission.
    pub emitted_event_ids: Vec<String>,
}

/// Persist response for one admission chain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LifecyclePersistResponse {
    /// Committed capture transition (genesis raw input).
    pub capture_operation_id: OperationIdentity,
    /// Committed capture receipt envelope.
    pub capture_receipt: ReceiptEnvelope,
    /// Emitted event ids of the capture transition.
    pub capture_emitted_event_ids: Vec<String>,
    /// True when the capture replayed an already-admitted identity.
    pub capture_replayed: bool,
    /// One committed audit leg per hop, in chain order.
    pub hops: Vec<PersistedHop>,
    /// One linkage binding per hop, in chain order.
    pub links: Vec<LinkAuditBinding>,
}

/// Front-door errors for lifecycle persistence.
#[derive(Debug, Error)]
pub enum LifecyclePersistError {
    /// A field failed bounded identity validation.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason code.
        reason: &'static str,
    },
    /// The presented chain failed curation verification.
    #[error("lifecycle chain rejected: {0}")]
    ChainRejected(String),
    /// The presented fence does not match live service authority.
    #[error("lifecycle persist fence mismatch")]
    FenceMismatch,
    /// An operation identity collides with different executable bytes.
    #[error("lifecycle persist operation identity conflict")]
    IdentityConflict,
    /// A canonical request hash does not match the admitted bytes.
    #[error("lifecycle persist canonical request digest mismatch")]
    DigestMismatch,
    /// The store refused to commit an admitted transition.
    #[error("lifecycle persist transition was not committed")]
    NotCommitted,
    /// The store manifest digest does not match the admitted catalogue.
    #[error("lifecycle persist operation manifest mismatch")]
    ManifestMismatch,
    /// The store committed no response receipt; the outcome is unknown.
    #[error("lifecycle persist response receipt is missing; outcome is unknown")]
    MissingReceiptEnvelope,
    /// A closed store error.
    #[error("lifecycle persist store: {0}")]
    Store(#[from] StoreError),
    /// A Kernel service error.
    #[error("lifecycle persist service: {0}")]
    Service(#[from] KernelServiceError),
}

impl LifecyclePersistError {
    /// Maps a store error without manufacturing authority.
    pub fn from_store(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Persists one verified admission chain: immutable raw capture plus one
/// hash-chained audit leg per hop.
///
/// Validates the session, fence, and request shape; re-verifies the
/// chain through the curation owner; pre-builds every transition and
/// verifies every sealed hash before the first commit; then commits
/// sequentially, chaining each audit leg to the previous committed
/// hash. A mid-chain commit failure stops with an error while earlier
/// hops stay committed and receipted — resuming re-issues the same
/// request and replays sealed hops without remutation.
pub async fn handle_lifecycle_persist_request(
    client: &impl CanonicalStoreClient,
    service: &KernelService,
    session: &AuthenticatedLifecycleSession,
    request: &LifecyclePersistRequest,
) -> Result<LifecyclePersistResponse, LifecyclePersistError> {
    let context = session
        .service_context(service)
        .map_err(LifecyclePersistError::Service)?;
    validate_persist_request(request)?;
    require_live_fence(&context, &request.state_fence)?;
    if request.context.state_fence != request.state_fence {
        return Err(LifecyclePersistError::FenceMismatch);
    }
    verify_admission_chain(&request.chain)
        .map_err(|error| LifecyclePersistError::ChainRejected(error.to_string()))?;
    let transitions = build_persist_transitions(request)?;
    for ((transition, _), identity) in transitions.iter().zip(request.hop_identities.iter()) {
        let check = CanonicalRequestView::from_apply(&request.context, transition, &[], &[]);
        verify_canonical_request_hash(&check, &identity.canonical_request_hash)
            .map_err(|_| LifecyclePersistError::DigestMismatch)?;
    }
    // Genesis capture commits first; each audit leg chains to its
    // predecessor by appointed identity (exact, sealing-stable).
    let (capture_transition, _) = &transitions[0];
    let (capture_receipt, capture_replayed) =
        commit_transition(client, request, capture_transition).await?;
    let capture_envelope = capture_receipt
        .require_reconciliation_envelope()
        .map_err(LifecyclePersistError::from_store)?
        .clone();
    let capture_emitted: Vec<String> = capture_receipt
        .emitted_event_ids
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut hops = Vec::with_capacity(request.chain.len());
    let mut links = Vec::with_capacity(request.chain.len());
    for index in 0..request.chain.len() {
        let transition = &transitions[index + 1].0;
        let (receipt, replayed) = commit_transition(client, request, transition).await?;
        let emitted: Vec<String> = receipt
            .emitted_event_ids
            .iter()
            .map(ToString::to_string)
            .collect();
        let audit_operation_id = transition.identity.operation_id.clone();
        hops.push(PersistedHop {
            curation_receipt_id: request.chain[index].receipt.receipt_id.as_str().to_owned(),
            operation_id: transition.identity.clone(),
            receipt: receipt
                .require_reconciliation_envelope()
                .map_err(LifecyclePersistError::from_store)?
                .clone(),
            emitted_event_ids: emitted.clone(),
            replayed,
        });
        links.push(LinkAuditBinding {
            curation_receipt_id: request.chain[index].receipt.receipt_id.as_str().to_owned(),
            audit_operation_id: audit_operation_id.to_string(),
            emitted_event_ids: emitted,
        });
    }
    Ok(LifecyclePersistResponse {
        capture_operation_id: capture_transition.identity.clone(),
        capture_receipt: capture_envelope,
        capture_emitted_event_ids: capture_emitted,
        capture_replayed,
        hops,
        links,
    })
}

/// Builds every transition for a persist request without committing.
///
/// Public so the route owner seals each identity hash before dispatch:
/// the builder is deterministic over the request, so dispatch rebuilds
/// byte-identical transitions. Returns one capture transition plus one
/// audit transition per hop, each paired with the active manifest
/// digest.
pub fn build_persist_transitions(
    request: &LifecyclePersistRequest,
) -> Result<
    Vec<(PreparedTransition, eliot_store_api::OperationManifestDigest)>,
    LifecyclePersistError,
> {
    validate_persist_request(request)?;
    verify_admission_chain(&request.chain)
        .map_err(|error| LifecyclePersistError::ChainRejected(error.to_string()))?;
    let manifest_digest = operation_manifest_set_digest(&generated_operation_manifests()?)
        .map_err(|_| LifecyclePersistError::ManifestMismatch)?;
    let scope = ScopeId::new(request.chain[0].receipt.scope.as_str()).map_err(|_| {
        LifecyclePersistError::InvalidField {
            field: "lifecycle.persist.scope",
            reason: "chain scope identity is invalid",
        }
    })?;
    let chain_scope = format!(
        "lifecycle-chain:{}",
        request.chain[0].receipt.output_record_id.as_str()
    );
    let ordering =
        OrderingScopeId::new(chain_scope).map_err(|_| LifecyclePersistError::InvalidField {
            field: "lifecycle.persist.chain",
            reason: "chain ordering scope identity is invalid",
        })?;
    let session_id =
        request
            .context
            .session_id
            .clone()
            .ok_or(LifecyclePersistError::InvalidField {
                field: "lifecycle.persist.session",
                reason: "bound session is required",
            })?;
    let mut admission_view = request.clone();
    for identity in &mut admission_view.hop_identities {
        identity.canonical_request_hash = String::new();
    }
    let admission_digest = sha256_hex(
        &canonical_json_bytes(&admission_view)
            .map_err(|_| LifecyclePersistError::DigestMismatch)?,
    );
    let mut built = Vec::with_capacity(request.hop_identities.len());
    let genesis = &request.chain[0];
    if genesis.operation != CurationMutationOperation::CaptureObservation {
        return Err(LifecyclePersistError::ChainRejected(
            "chain must start from a CaptureObservation genesis".to_owned(),
        ));
    }
    let bindings = TransitionBindings {
        fence: request.state_fence.clone(),
        task_id: request.context.task_id.clone().map(|task| task.to_string()),
        scope,
        ordering,
        manifest_digest,
        admission_digest,
    };
    built.push((
        transition_for(
            &request.hop_identities[0],
            &bindings,
            vec![capture_command(genesis)?],
            vec![event_id_for(&genesis.receipt.receipt_id)?],
        )?,
        bindings.manifest_digest.clone(),
    ));
    for (index, admission) in request.chain.iter().enumerate() {
        let expected_audit = request.hop_identities[index + 1].operation_id.to_string();
        let preset = admission.receipt.audit_event_id.clone().ok_or(
            LifecyclePersistError::InvalidField {
                field: "lifecycle.persist.audit_event",
                reason: "every admission must preset its audit event",
            },
        )?;
        if preset.as_str() != expected_audit {
            return Err(LifecyclePersistError::InvalidField {
                field: "lifecycle.persist.audit_event",
                reason: "preset audit event must equal the appointed audit identity",
            });
        }
        let previous_operation_id = request.hop_identities[index].operation_id.to_string();
        built.push((
            transition_for(
                &request.hop_identities[index + 1],
                &bindings,
                vec![audit_command(
                    admission,
                    &request.hop_identities[index + 1],
                    &session_id,
                    &previous_operation_id,
                    index + 1,
                )],
                vec![event_id_for(&admission.receipt.receipt_id)?],
            )?,
            bindings.manifest_digest.clone(),
        ));
    }
    Ok(built)
}

/// Commits one transition with receipt pre-check, validation, and
/// replay reporting. A sealed identity resolves its receipt without
/// remutation; a divergent seal conflicts; otherwise the transition
/// commits exactly once.
async fn commit_transition(
    client: &impl CanonicalStoreClient,
    request: &LifecyclePersistRequest,
    transition: &PreparedTransition,
) -> Result<(eliot_store_api::WriteReceipt, bool), LifecyclePersistError> {
    if let Some(existing) = client
        .receipt(transition.identity.operation_id.clone())
        .await
        .map_err(LifecyclePersistError::from_store)?
    {
        if existing.canonical_request_hash != transition.identity.canonical_request_hash
            || existing.idempotency_key != transition.identity.idempotency_key
        {
            return Err(LifecyclePersistError::IdentityConflict);
        }
        return Ok((existing, true));
    }
    let receipt = client
        .apply_prepared(&request.context, transition.clone(), Vec::new(), Vec::new())
        .await
        .map_err(LifecyclePersistError::from_store)?;
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed {
        return Err(LifecyclePersistError::NotCommitted);
    }
    receipt
        .validate()
        .map_err(LifecyclePersistError::from_store)?;
    if receipt.state_fence != request.state_fence {
        return Err(LifecyclePersistError::FenceMismatch);
    }
    if receipt.operation_manifest_digest != transition.operation_manifest_digest {
        return Err(LifecyclePersistError::ManifestMismatch);
    }
    Ok((receipt, false))
}

fn validate_persist_request(
    request: &LifecyclePersistRequest,
) -> Result<(), LifecyclePersistError> {
    let invalid = |field: &'static str| LifecyclePersistError::InvalidField {
        field,
        reason: "persist request failed closed validation",
    };
    request
        .context
        .validate()
        .map_err(|_| invalid("lifecycle.persist.context"))?;
    if request.chain.is_empty() {
        return Err(invalid("lifecycle.persist.chain"));
    }
    if request.hop_identities.len() != request.chain.len() + 1 {
        return Err(invalid("lifecycle.persist.hop_identities"));
    }
    for identity in &request.hop_identities {
        identity
            .validate()
            .map_err(|_| invalid("lifecycle.persist.identity"))?;
    }
    let scope = request.chain[0].receipt.scope.as_str();
    for admission in &request.chain {
        if admission.receipt.scope.as_str() != scope {
            return Err(invalid("lifecycle.persist.scope"));
        }
        if admission.receipt.state_fence != request.state_fence {
            return Err(LifecyclePersistError::FenceMismatch);
        }
    }
    Ok(())
}

fn require_live_fence(
    context: &LifecycleServiceContext,
    fence: &StateFence,
) -> Result<(), LifecyclePersistError> {
    if !fence
        .authority_epoch
        .is_same_authority(&context.authority_epoch)
    {
        return Err(LifecyclePersistError::FenceMismatch);
    }
    let generation =
        eliot_contracts::ResourceGeneration::new(context.generation).map_err(|_| {
            LifecyclePersistError::InvalidField {
                field: "lifecycle.persist.generation",
                reason: "live generation is not a valid resource generation",
            }
        })?;
    if fence.resource_generation != generation {
        return Err(LifecyclePersistError::FenceMismatch);
    }
    fence
        .validate()
        .map_err(|_| LifecyclePersistError::FenceMismatch)?;
    Ok(())
}

fn event_id_for(receipt_id: &ArtifactId) -> Result<EventId, LifecyclePersistError> {
    EventId::new(receipt_id.as_str()).map_err(|_| LifecyclePersistError::InvalidField {
        field: "lifecycle.persist.receipt",
        reason: "curation receipt identity is not an event identity",
    })
}

fn capture_command(
    admission: &CurationAdmission,
) -> Result<NamedMutationRequest, LifecyclePersistError> {
    if admission.operation != CurationMutationOperation::CaptureObservation {
        return Err(LifecyclePersistError::ChainRejected(
            "genesis hop must carry CaptureObservation".to_owned(),
        ));
    }
    let mut parameters = std::collections::BTreeMap::new();
    parameters.insert(
        "subject".to_owned(),
        Value::String(admission.receipt.output_record_id.as_str().to_owned()),
    );
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::CaptureObservation,
        parameters,
    })
}

fn audit_command(
    admission: &CurationAdmission,
    identity: &OperationIdentity,
    session_id: &SessionId,
    previous_operation_id: &str,
    position: usize,
) -> NamedMutationRequest {
    let mut parameters = std::collections::BTreeMap::new();
    parameters.insert(
        "operation_id".to_owned(),
        Value::String(identity.operation_id.to_string()),
    );
    parameters.insert(
        "idempotency_key".to_owned(),
        Value::String(identity.idempotency_key.clone()),
    );
    parameters.insert(
        "session_id".to_owned(),
        Value::String(session_id.as_str().to_owned()),
    );
    parameters.insert(
        "access_digest".to_owned(),
        Value::String(admission.receipt.digest.clone()),
    );
    // Chain continuity binds the previous link by appointed identity:
    // the digest is stable across hash sealing (identities are), so the
    // rebuilt transition verifies byte-identical. Resolve the named
    // operation to check the committed hash behind it.
    parameters.insert(
        "action_digest".to_owned(),
        Value::String(sha256_hex(previous_operation_id.as_bytes())),
    );
    parameters.insert(
        "expected_revision".to_owned(),
        Value::String(position.to_string()),
    );
    NamedMutationRequest {
        operation: NamedMutationOperation::AppendAuditEvent,
        parameters,
    }
}

/// Loop-invariant transition bindings shared by one persist call.
struct TransitionBindings {
    fence: StateFence,
    task_id: Option<String>,
    scope: ScopeId,
    ordering: OrderingScopeId,
    manifest_digest: eliot_store_api::OperationManifestDigest,
    admission_digest: String,
}

fn transition_for(
    identity: &OperationIdentity,
    bindings: &TransitionBindings,
    commands: Vec<NamedMutationRequest>,
    events: Vec<EventId>,
) -> Result<PreparedTransition, LifecyclePersistError> {
    let transition = PreparedTransition {
        identity: identity.clone(),
        state_fence: bindings.fence.clone(),
        scope_id: bindings.scope.clone(),
        task_id: bindings.task_id.clone(),
        ordering_scopes: vec![bindings.ordering.clone()],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: bindings.admission_digest.clone(),
        operation_manifest_digest: bindings.manifest_digest.clone(),
        named_operations: commands,
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: events,
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    transition
        .validate()
        .map_err(LifecyclePersistError::from_store)?;
    Ok(transition)
}
