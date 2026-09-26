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
//! per hop i with a caller-supplied typed mutation:
//!   T_mut(i) = [ApplyEpistemicRevision { revision: <exact payload> }]
//!            | [ApplyLifecyclePolicy { six declared fields }]
//! Ti+1 = [AppendAuditEvent {
//!     operation_id: own transition id (== receipt preset audit event),
//!     idempotency_key: own key,
//!     session_id: bound session,
//!     access_digest: hop curation receipt digest,
//!     action_digest: sha256 of the previous commit-order identity,
//!     expected_revision: 1-based hop position,
//! }]
//! ```
//!
//! Mutation legs carry the complete persisted fields: the revision
//! `revision` parameter holds the full [`EpistemicRevisionPayload`]
//! (position, expected revision, candidate scope/fence/evidence,
//! transition) and the policy leg the exact six-field package, so the
//! chain stays reconstructible after reload through the owner readback
//! (`EpistemicCommit::from_prepared`). Mutation legs emit no lifecycle
//! events of their own (mirroring the Governor-owned policy legs);
//! linkage flows through the adjacent audit legs only.
//!
//! Each audit transition carries `event_ids = [curation receipt id]`, so
//! the committed `WriteReceipt.emitted_event_ids` bind back to the
//! admission through the returned [`LinkAuditBinding`]; the curation
//! side links with its own `link_audit` (digest already covers the
//! preset event). Mutation legs are never fabricated from a receipt:
//! the legitimate caller presents the exact typed canonical payload
//! (Governor-admitted `EpistemicRevisionPayload`) or the owner-built
//! policy command alongside the admitted transition, and the seam
//! validates payload/transition identities, scope/fence lineage, and
//! authority before applying the declared named mutations. Resuming an
//! interrupted chain re-issues the same request: sealed legs replay
//! without remutation.

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
    epistemic_revision::{EpistemicCommit, EpistemicRevisionPayload},
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
    /// Caller-supplied typed mutation legs, index-aligned to `chain`.
    /// Exactly `chain.len()` entries; the genesis entry is always `None`
    /// (its mutation is the capture itself). A revision/policy hop
    /// carries its exact canonical payload or owner-built command;
    /// hops without one persist linkage only.
    pub hop_mutations: Vec<Option<HopMutationInput>>,
}

/// Caller-supplied typed mutation leg for one revision/policy hop.
///
/// The legitimate caller (Governor-owned admission path) presents the
/// exact canonical payload or the owner-built command together with the
/// admitted transition and the Governor request metadata for this leg.
/// The seam validates every binding and never fabricates payload content.
#[derive(Clone, Debug, Serialize)]
pub struct HopMutationInput {
    /// Caller-appointed transition identity. For revision legs this must
    /// equal the payload candidate's own operation/idempotency binding.
    pub identity: OperationIdentity,
    /// Governor request metadata for this leg. For revision legs the
    /// owner readback requires request/task/product/fence agreement
    /// with the payload candidate.
    pub context: RequestMetadata,
    /// The exact typed mutation.
    pub mutation: HopMutation,
    /// Caller-supplied proof/approval refs carried on the transition.
    /// The seam carries them verbatim and mints none.
    pub proof_refs: Vec<String>,
}

/// Exact typed mutation for one hop.
#[derive(Clone, Debug, Serialize)]
pub enum HopMutation {
    /// Governor-admitted epistemic position payload. The seam builds the
    /// exact `ApplyEpistemicRevision{revision}` command through the
    /// payload owner's constructor and binds it through the owner's
    /// readback validation.
    Revision(Box<EpistemicRevisionPayload>),
    /// Owner-built `ApplyLifecyclePolicy` command carrying the exact
    /// declared six-field package. Semantic policy content stays
    /// skill-owner-admitted; the seam checks operation, declared shape,
    /// fence, scope, and chain position only.
    Policy(NamedMutationRequest),
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
    /// One committed mutation leg per revision/policy hop, in chain order.
    pub mutations: Vec<PersistedMutation>,
}

/// One persisted mutation leg: the committed revision/policy transition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PersistedMutation {
    /// Chain position of the hop this leg persists.
    pub hop_index: usize,
    /// Curation receipt identity this leg persists.
    pub curation_receipt_id: String,
    /// Committed mutation transition operation identity.
    pub operation_id: OperationIdentity,
    /// Exact store response receipt (never fabricated by the caller).
    pub receipt: ReceiptEnvelope,
    /// Emitted event ids of the mutation transition.
    pub emitted_event_ids: Vec<String>,
    /// True when the leg replayed an already-admitted identity.
    pub replayed: bool,
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
    /// A closed store error (including the store's own missing-envelope
    /// case from `require_reconciliation_envelope`; never duplicated here).
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
    let legs = build_persist_transitions(request)?;
    for leg in &legs {
        let check = CanonicalRequestView::from_apply(&leg.context, &leg.transition, &[], &[]);
        verify_canonical_request_hash(&check, &leg.appointed.canonical_request_hash)
            .map_err(|_| LifecyclePersistError::DigestMismatch)?;
    }
    // Genesis capture commits first; mutation and audit legs follow in
    // commit order, each chained to its predecessor by appointed
    // identity (exact, sealing-stable).
    let mut legs_iter = legs.iter();
    let capture_leg = legs_iter
        .next()
        .ok_or(LifecyclePersistError::InvalidField {
            field: "lifecycle.persist.chain",
            reason: "persist request failed closed validation",
        })?;
    let (capture_receipt, capture_replayed) =
        commit_transition(client, &capture_leg.context, &capture_leg.transition).await?;
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
    let mut mutations = Vec::new();
    for leg in legs_iter {
        let (receipt, replayed) = commit_transition(client, &leg.context, &leg.transition).await?;
        let emitted: Vec<String> = receipt
            .emitted_event_ids
            .iter()
            .map(ToString::to_string)
            .collect();
        let operation_id = leg.transition.identity.clone();
        let envelope = receipt
            .require_reconciliation_envelope()
            .map_err(LifecyclePersistError::from_store)?
            .clone();
        match leg.kind {
            BuiltLegKind::Mutation { hop } => mutations.push(PersistedMutation {
                hop_index: hop,
                curation_receipt_id: request.chain[hop].receipt.receipt_id.as_str().to_owned(),
                operation_id: operation_id.clone(),
                receipt: envelope,
                emitted_event_ids: emitted,
                replayed,
            }),
            BuiltLegKind::Audit { hop } => {
                hops.push(PersistedHop {
                    curation_receipt_id: request.chain[hop].receipt.receipt_id.as_str().to_owned(),
                    operation_id: operation_id.clone(),
                    receipt: envelope,
                    emitted_event_ids: emitted.clone(),
                    replayed,
                });
                links.push(LinkAuditBinding {
                    curation_receipt_id: request.chain[hop].receipt.receipt_id.as_str().to_owned(),
                    audit_operation_id: operation_id.operation_id.to_string(),
                    emitted_event_ids: emitted,
                });
            }
            BuiltLegKind::Capture => {
                return Err(LifecyclePersistError::InvalidField {
                    field: "lifecycle.persist.chain",
                    reason: "capture leg must open the commit order exactly once",
                });
            }
        }
    }
    Ok(LifecyclePersistResponse {
        capture_operation_id: capture_leg.transition.identity.clone(),
        capture_receipt: capture_envelope,
        capture_emitted_event_ids: capture_emitted,
        capture_replayed,
        hops,
        links,
        mutations,
    })
}

/// One sealed leg in commit order with the exact context it commits
/// under.
///
/// Public so the route owner seals each identity hash before dispatch:
/// the builder is deterministic over the request, so dispatch rebuilds
/// byte-identical legs. Each leg verifies against its own context
/// (lifecycle context for capture/audit legs, Governor leg metadata
/// for mutation legs).
#[derive(Clone, Debug)]
pub struct BuiltLeg {
    /// The exact transition to commit.
    pub transition: PreparedTransition,
    /// The caller-appointed identity carrying the sealed hash.
    pub appointed: OperationIdentity,
    /// The exact request metadata the leg commits under.
    pub context: RequestMetadata,
    /// Position of this leg in the persist layout.
    pub kind: BuiltLegKind,
}

/// Position of one built leg in the persist layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltLegKind {
    /// Genesis capture, opens the commit order exactly once.
    Capture,
    /// Revision/policy mutation leg for one hop.
    Mutation {
        /// Chain position of the hop this leg persists.
        hop: usize,
    },
    /// Audit linkage leg for one hop.
    Audit {
        /// Chain position of the hop this leg links.
        hop: usize,
    },
}

/// Builds every leg for a persist request without committing.
///
/// Returns the capture leg plus, per hop in chain order, the optional
/// mutation leg followed by the audit leg. Audit legs chain to the
/// previous commit-order identity (the hop's mutation leg when one
/// exists), so sealing stays stable across rebuilds.
pub fn build_persist_transitions(
    request: &LifecyclePersistRequest,
) -> Result<Vec<BuiltLeg>, LifecyclePersistError> {
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
    for input in admission_view
        .hop_mutations
        .iter_mut()
        .filter_map(|slot| slot.as_mut())
    {
        input.identity.canonical_request_hash = String::new();
    }
    let admission_digest = sha256_hex(
        &canonical_json_bytes(&admission_view)
            .map_err(|_| LifecyclePersistError::DigestMismatch)?,
    );
    let mut built = Vec::with_capacity(
        request.hop_identities.len() + request.hop_mutations.iter().flatten().count(),
    );
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
    let capture_identity = request.hop_identities[0].clone();
    let capture_transition = transition_for(
        &capture_identity,
        &bindings,
        TransitionSpec {
            class: TransitionClass::CaptureCandidate,
            ceiling: EffectClass::Candidate,
            task_id: bindings.task_id.clone(),
            commands: vec![capture_command(genesis)?],
            events: vec![event_id_for(&genesis.receipt.receipt_id)?],
            proof_refs: Vec::new(),
        },
    )?;
    built.push(BuiltLeg {
        transition: capture_transition,
        appointed: capture_identity,
        context: request.context.clone(),
        kind: BuiltLegKind::Capture,
    });
    // Previous commit-order identity, for audit chain continuity: the
    // hop's mutation leg when one exists, else the previous audit leg.
    let mut previous_operation_id = request.hop_identities[0].operation_id.to_string();
    for (index, admission) in request.chain.iter().enumerate() {
        let (mut legs, next) = hop_legs_for(&HopLegParams {
            index,
            admission,
            audit_identity: &request.hop_identities[index + 1],
            mutation: request.hop_mutations[index].as_ref(),
            session_id: &session_id,
            previous_operation_id: &previous_operation_id,
            bindings: &bindings,
            lifecycle_context: &request.context,
        })?;
        previous_operation_id = next;
        built.append(&mut legs);
    }
    Ok(built)
}

/// Commits one transition with receipt pre-check, validation, and
/// replay reporting. A sealed identity resolves its receipt without
/// remutation; a divergent seal conflicts; otherwise the transition
/// commits exactly once.
async fn commit_transition(
    client: &impl CanonicalStoreClient,
    context: &RequestMetadata,
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
        .apply_prepared(context, transition.clone(), Vec::new(), Vec::new())
        .await
        .map_err(LifecyclePersistError::from_store)?;
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed {
        return Err(LifecyclePersistError::NotCommitted);
    }
    receipt
        .validate()
        .map_err(LifecyclePersistError::from_store)?;
    if receipt.state_fence != transition.state_fence {
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
    if request.hop_mutations.len() != request.chain.len() {
        return Err(invalid("lifecycle.persist.hop_mutations"));
    }
    // The genesis mutation is the capture itself; a mutation leg for hop
    // zero would double-persist the raw input.
    if request.hop_mutations[0].is_some() {
        return Err(invalid("lifecycle.persist.hop_mutations"));
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
    for (index, slot) in request.hop_mutations.iter().enumerate() {
        if let Some(input) = slot {
            validate_mutation_input(input, &request.chain[index], request)?;
        }
    }
    Ok(())
}

/// Validates one caller-supplied mutation leg against its admitted
/// transition: payload/transition identities, scope/fence lineage, and
/// authority. Revision legs additionally bind through the payload
/// owner's transition check; policy legs through the declared shape
/// table. Lineage note: the lifecycle `supersedes` record handles and
/// the epistemic position `predecessor` live in different namespaces
/// (record lineage vs position-revision lineage), so no equation
/// between them is enforced — scope, fence, identity, and audit
/// appointment are the cross-owner bindings.
fn validate_mutation_input(
    input: &HopMutationInput,
    admission: &CurationAdmission,
    request: &LifecyclePersistRequest,
) -> Result<(), LifecyclePersistError> {
    let invalid = |field: &'static str| LifecyclePersistError::InvalidField {
        field,
        reason: "mutation leg failed closed validation",
    };
    input
        .identity
        .validate()
        .map_err(|_| invalid("lifecycle.persist.mutation.identity"))?;
    input
        .context
        .validate()
        .map_err(|_| invalid("lifecycle.persist.mutation.context"))?;
    if input.context.state_fence != request.state_fence {
        return Err(LifecyclePersistError::FenceMismatch);
    }
    match &input.mutation {
        HopMutation::Revision(payload) => {
            payload
                .validate()
                .map_err(LifecyclePersistError::from_store)?;
            if admission.operation != CurationMutationOperation::ApplyEpistemicRevision {
                return Err(invalid("lifecycle.persist.mutation"));
            }
            if payload.candidate.scope != admission.receipt.scope.as_str() {
                return Err(invalid("lifecycle.persist.mutation.scope"));
            }
            if payload.candidate.fence != admission.receipt.state_fence {
                return Err(LifecyclePersistError::FenceMismatch);
            }
            if input.identity.operation_id != payload.candidate.operation_id
                || input.identity.idempotency_key != payload.candidate.idempotency_key
            {
                return Err(invalid("lifecycle.persist.mutation.identity"));
            }
            if input.context.request_id != payload.candidate.request_id
                || input.context.task_id.as_ref() != Some(&payload.candidate.task_id)
                || input.context.product_id != payload.candidate.work_scope.product_id
            {
                return Err(invalid("lifecycle.persist.mutation.context"));
            }
        }
        HopMutation::Policy(command) => {
            if command.operation != NamedMutationOperation::ApplyLifecyclePolicy {
                return Err(invalid("lifecycle.persist.mutation"));
            }
            // Declared six-field shape is enforced by the owner
            // catalogue gate at build; semantic policy content stays
            // skill-owner-admitted.
            if admission.operation != CurationMutationOperation::ApplyLifecyclePolicy {
                return Err(invalid("lifecycle.persist.mutation"));
            }
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

/// Builds one revision/policy mutation leg from caller-supplied exact
/// input. The revision command is built through the payload owner's
/// constructor and the finished transition is bound through the owner's
/// readback validation; the policy command arrives owner-built. Every
/// mutation leg additionally passes the owner catalogue gate (declared
/// membership, class/ceiling, exact typed parameters) before it may
/// seal.
fn mutation_transition_for(
    input: &HopMutationInput,
    admission: &CurationAdmission,
    bindings: &TransitionBindings,
) -> Result<PreparedTransition, LifecyclePersistError> {
    let transition = match &input.mutation {
        HopMutation::Revision(payload) => {
            let command = payload
                .command()
                .map_err(LifecyclePersistError::from_store)?;
            let mut transition = PreparedTransition {
                identity: input.identity.clone(),
                state_fence: bindings.fence.clone(),
                scope_id: ScopeId::new(payload.candidate.scope.as_str()).map_err(|_| {
                    LifecyclePersistError::InvalidField {
                        field: "lifecycle.persist.mutation.scope",
                        reason: "payload scope identity is invalid",
                    }
                })?,
                task_id: Some(payload.candidate.task_id.to_string()),
                ordering_scopes: vec![bindings.ordering.clone()],
                transition_class: TransitionClass::Epistemic,
                requested_effect_ceiling: TransitionClass::Epistemic.maximum_effect(),
                admission_contract_set_digest: bindings.admission_digest.clone(),
                semantic_source_revisions: Vec::new(),
                admission_digest: String::new(),
                operation_manifest_digest: bindings.manifest_digest.clone(),
                mutation_plan_digest: String::new(),
                named_operations: vec![command],
                event_projection_relation_intents: EventProjectionRelationIntents {
                    event_ids: Vec::new(),
                    projection_kinds: Vec::new(),
                    relation_kinds: Vec::new(),
                },
                security: SecurityContext::default(),
                required_proof_and_approval_refs: input.proof_refs.clone(),
            };
            // Issue #18: the persist legs dispatch with no expected revision
            // heads, so no source revisions are bound; the plan and admission
            // digests still derive from the exact admitted transition.
            eliot_store_api::bind_issue18_digests(&mut transition, Vec::new())
                .map_err(LifecyclePersistError::from_store)?;
            transition
                .validate()
                .map_err(LifecyclePersistError::from_store)?;
            // Owner bind: payload, prepared transition, and Governor leg
            // metadata must agree exactly; a missing revision command
            // here is an internal construction fault, never caller data.
            let commit = EpistemicCommit::from_prepared(&input.context, &transition)
                .map_err(LifecyclePersistError::from_store)?
                .ok_or(LifecyclePersistError::InvalidField {
                    field: "lifecycle.persist.mutation",
                    reason: "revision leg carries no revision command",
                })?;
            if commit.payload != **payload {
                return Err(LifecyclePersistError::InvalidField {
                    field: "lifecycle.persist.mutation",
                    reason: "revision readback disagrees with the presented payload",
                });
            }
            transition
        }
        HopMutation::Policy(command) => transition_for(
            &input.identity,
            bindings,
            TransitionSpec {
                class: TransitionClass::LifecyclePolicy,
                ceiling: EffectClass::ReversibleMutation,
                task_id: bindings.task_id.clone(),
                commands: vec![command.clone()],
                events: Vec::new(),
                proof_refs: input.proof_refs.clone(),
            },
        )?,
    };
    transition
        .validate_against_catalogue(
            &generated_operation_manifests().map_err(LifecyclePersistError::from_store)?,
        )
        .map_err(LifecyclePersistError::from_store)?;
    let _ = admission;
    Ok(transition)
}

fn transition_for(
    identity: &OperationIdentity,
    bindings: &TransitionBindings,
    spec: TransitionSpec,
) -> Result<PreparedTransition, LifecyclePersistError> {
    let mut transition = PreparedTransition {
        identity: identity.clone(),
        state_fence: bindings.fence.clone(),
        scope_id: bindings.scope.clone(),
        task_id: spec.task_id,
        ordering_scopes: vec![bindings.ordering.clone()],
        transition_class: spec.class,
        requested_effect_ceiling: spec.ceiling,
        admission_contract_set_digest: bindings.admission_digest.clone(),
        semantic_source_revisions: Vec::new(),
        admission_digest: String::new(),
        operation_manifest_digest: bindings.manifest_digest.clone(),
        mutation_plan_digest: String::new(),
        named_operations: spec.commands,
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: spec.events,
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: spec.proof_refs,
    };
    // Issue #18: the persist legs dispatch with no expected revision heads,
    // so no source revisions are bound; the plan and admission digests still
    // derive from the exact admitted transition.
    eliot_store_api::bind_issue18_digests(&mut transition, Vec::new())
        .map_err(LifecyclePersistError::from_store)?;
    transition
        .validate()
        .map_err(LifecyclePersistError::from_store)?;
    Ok(transition)
}

/// Per-leg transition shape: class, ceiling, task, commands, events, refs.
struct TransitionSpec {
    class: TransitionClass,
    ceiling: EffectClass,
    task_id: Option<String>,
    commands: Vec<NamedMutationRequest>,
    events: Vec<EventId>,
    proof_refs: Vec<String>,
}

/// One hop's leg inputs for [`hop_legs_for`].
struct HopLegParams<'a> {
    index: usize,
    admission: &'a CurationAdmission,
    audit_identity: &'a OperationIdentity,
    mutation: Option<&'a HopMutationInput>,
    session_id: &'a SessionId,
    previous_operation_id: &'a str,
    bindings: &'a TransitionBindings,
    lifecycle_context: &'a RequestMetadata,
}

/// Builds one hop's legs in commit order — the optional mutation leg
/// followed by the audit leg — and returns them with the next previous
/// commit-order identity for chain continuity.
fn hop_legs_for(
    params: &HopLegParams<'_>,
) -> Result<(Vec<BuiltLeg>, String), LifecyclePersistError> {
    let HopLegParams {
        index,
        admission,
        audit_identity,
        mutation,
        session_id,
        previous_operation_id,
        bindings,
        lifecycle_context,
    } = params;
    let preset =
        admission
            .receipt
            .audit_event_id
            .clone()
            .ok_or(LifecyclePersistError::InvalidField {
                field: "lifecycle.persist.audit_event",
                reason: "every admission must preset its audit event",
            })?;
    if preset.as_str() != audit_identity.operation_id.to_string() {
        return Err(LifecyclePersistError::InvalidField {
            field: "lifecycle.persist.audit_event",
            reason: "preset audit event must equal the appointed audit identity",
        });
    }
    let mut legs = Vec::with_capacity(2);
    let mut previous: String = (*previous_operation_id).to_owned();
    if let Some(input) = mutation {
        let mutation_transition = mutation_transition_for(input, admission, bindings)?;
        previous = input.identity.operation_id.to_string();
        legs.push(BuiltLeg {
            transition: mutation_transition,
            appointed: input.identity.clone(),
            context: input.context.clone(),
            kind: BuiltLegKind::Mutation { hop: *index },
        });
    }
    let audit_transition = transition_for(
        audit_identity,
        bindings,
        TransitionSpec {
            class: TransitionClass::CaptureCandidate,
            ceiling: EffectClass::Candidate,
            task_id: bindings.task_id.clone(),
            commands: vec![audit_command(
                admission,
                audit_identity,
                session_id,
                &previous,
                index + 1,
            )],
            events: vec![event_id_for(&admission.receipt.receipt_id)?],
            proof_refs: Vec::new(),
        },
    )?;
    previous = audit_identity.operation_id.to_string();
    legs.push(BuiltLeg {
        transition: audit_transition,
        appointed: (*audit_identity).clone(),
        context: (*lifecycle_context).clone(),
        kind: BuiltLegKind::Audit { hop: *index },
    });
    Ok((legs, previous))
}
