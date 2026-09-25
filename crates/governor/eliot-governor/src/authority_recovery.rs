//! Typed authority-owner recovery for the Governor semantic boundary.
//!
//! Architecture traceability: `ARCH-AUTH-01` and `ARCH-SEC-02` require the
//! Governor to restore authority-owned state without minting authority;
//! `ARCH-RES-01`, `A13.6`, and `I1.8` bind recovery to one exact state fence;
//! `A13.6` keeps Kernel recovery opaque while this owner performs semantic
//! decoding. Implementation anchors are `P.3` and `I2.23`: the payload is
//! versioned and deny-unknown, and ordinary-module extraction does not create
//! a new provider or failure domain.
//!
//! Forbidden boundary: this module never issues leases, mints tokens,
//! activates effects, invents an empty replacement for non-empty durable
//! state, or lets Kernel decode these semantic records.

use super::CompositionError;
use crate::revocation_workflow::RevocationFanoutState;
use eliot_authority::{
    EffectAuthorizer, EffectAuthorizerRecoverySnapshot, GrantActivationRequest, GrantGraph,
    GrantGraphRecoverySnapshot, GrantRevocationRequest, GrantStatus, IntroductionActivationRequest,
    IntroductionRevocationRequest, IntroductionStatus, P07PortError, RevocationHistoryEvidence,
    SnapshotId, SuppressedGrant,
};
use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{EpochId, OperationId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_protocol::RequestIdentity;
use eliot_receipts::AuthorityBinding;
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationManifestDigest, OrderingHeadExpectation, OrderingScopeId, ScopeId, SecurityContext,
    TransitionClass, generated_operation_manifests, operation_manifest_set_digest,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Versioned semantic owner payload retained by Governor recovery.
pub const AUTHORITY_OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.authority-owner.v1";
pub const AUTHORITY_OWNER_SNAPSHOT_VERSION: u16 = 1;

/// Complete typed authority state bound to one outer Governor fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityOwnerSnapshot {
    /// Closed owner-payload schema identity.
    pub schema: String,
    /// Closed owner-payload schema version.
    pub version: u16,
    /// Exact Governor recovery fence.
    pub state_fence: StateFence,
    /// Full deterministic grant-lineage snapshot.
    pub grant_graph: GrantGraphRecoverySnapshot,
    /// Full deterministic effect-idempotency snapshot.
    pub effect_authorizer: EffectAuthorizerRecoverySnapshot,
    /// Durable owner hydration registry consumed before a closure bundle is
    /// served. `None` is an explicit empty registry; it is never synthesized
    /// from graph similarity at publish time.
    #[serde(default)]
    pub hydration_registry: Option<Vec<u8>>,
    /// Current compiled View and all derivative invalidation/rebuild/effect
    /// contest state produced by the last durable revocation fan-out.
    #[serde(default)]
    pub revocation_fanout: Option<RevocationFanoutState>,
}

impl AuthorityOwnerSnapshot {
    /// Constructs a typed payload after validating both authority snapshots.
    pub fn new(
        state_fence: StateFence,
        grant_graph: GrantGraphRecoverySnapshot,
        effect_authorizer: EffectAuthorizerRecoverySnapshot,
    ) -> Result<Self, CompositionError> {
        Self::with_hydration_registry(state_fence, grant_graph, effect_authorizer, None)
    }

    /// Constructs a complete owner snapshot with the exact durable hydration
    /// registry that will be imported before a closure bundle is served.
    pub fn with_hydration_registry(
        state_fence: StateFence,
        grant_graph: GrantGraphRecoverySnapshot,
        effect_authorizer: EffectAuthorizerRecoverySnapshot,
        hydration_registry: Option<Vec<u8>>,
    ) -> Result<Self, CompositionError> {
        let snapshot = Self {
            schema: AUTHORITY_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: AUTHORITY_OWNER_SNAPSHOT_VERSION,
            state_fence,
            grant_graph,
            effect_authorizer,
            hydration_registry,
            revocation_fanout: None,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Constructs the complete owner image including the durable derivative
    /// fan-out state restored from the Store owner record.
    pub fn with_recovery_state(
        state_fence: StateFence,
        grant_graph: GrantGraphRecoverySnapshot,
        effect_authorizer: EffectAuthorizerRecoverySnapshot,
        hydration_registry: Option<Vec<u8>>,
        revocation_fanout: Option<RevocationFanoutState>,
    ) -> Result<Self, CompositionError> {
        let snapshot = Self {
            schema: AUTHORITY_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: AUTHORITY_OWNER_SNAPSHOT_VERSION,
            state_fence,
            grant_graph,
            effect_authorizer,
            hydration_registry,
            revocation_fanout,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Validates schema, semantic authority state, and exact nested fences.
    pub fn validate(&self) -> Result<(), CompositionError> {
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.schema != AUTHORITY_OWNER_SNAPSHOT_SCHEMA
            || self.version != AUTHORITY_OWNER_SNAPSHOT_VERSION
        {
            return Err(CompositionError::Recovery(
                "authority owner snapshot has an invalid schema or version".to_owned(),
            ));
        }
        self.grant_graph
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        self.effect_authorizer
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self
            .grant_graph
            .grants
            .iter()
            .any(|grant| grant.binding.state_fence != self.state_fence)
        {
            return Err(CompositionError::Recovery(
                "authority grant snapshot contains a stale nested fence".to_owned(),
            ));
        }
        if self
            .effect_authorizer
            .records
            .iter()
            .any(|record| record.operation.state_fence != self.state_fence)
        {
            return Err(CompositionError::Recovery(
                "authority effect snapshot contains a stale nested fence".to_owned(),
            ));
        }
        if self
            .hydration_registry
            .as_ref()
            .is_some_and(|bytes| bytes.is_empty() || bytes.len() > 4 * 1024 * 1024)
        {
            return Err(CompositionError::Recovery(
                "authority owner hydration registry is empty or exceeds its bound".to_owned(),
            ));
        }
        if let Some(fanout) = &self.revocation_fanout {
            fanout.validate()?;
            if fanout.state_fence != self.state_fence {
                return Err(CompositionError::Recovery(
                    "authority revocation fan-out state has a stale owner fence".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn validate_against(&self, expected_fence: &StateFence) -> Result<(), CompositionError> {
        self.validate()?;
        if self.state_fence != *expected_fence {
            return Err(CompositionError::Recovery(
                "authority owner snapshot has a stale outer fence".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authenticated ingress identity for one durable Authority-owner projection
/// update.
///
/// The product event supplies the request identity and operation identity;
/// the Governor supplies the post-fan-out snapshot bytes. Keeping those
/// concerns separate prevents a caller from fabricating a durable owner image
/// while still making the owner-revision CAS explicit and replayable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityOwnerStateIngress {
    /// Identity admitted by the authenticated product event.
    pub identity: RequestIdentity,
    /// Stable canonical operation identity for the owner-state write.
    pub operation_id: OperationId,
    /// Exact owner revision observed before the fan-out update.
    pub expected_owner_revision: u64,
    /// Current canonical ordering-head sequence observed by ingress.
    pub expected_ordering_sequence: u64,
}

impl AuthorityOwnerStateIngress {
    /// Validates the authenticated owner-state ingress without touching Store.
    pub fn validate(&self) -> Result<(), CompositionError> {
        self.identity
            .validate()
            .map_err(|error| CompositionError::Provider(error.to_string()))?;
        if self.identity.request.state_fence != self.identity.request.metadata.state_fence {
            return Err(CompositionError::Provider(
                "authority owner-state request fence does not match its metadata".to_owned(),
            ));
        }
        if self.expected_owner_revision == 0 || self.expected_ordering_sequence == 0 {
            return Err(CompositionError::Owner(
                "authority owner-state expected revisions must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

const AUTHORITY_OWNER_STATE_SCOPE_ID: &str = "governor";
const AUTHORITY_OWNER_STATE_ORDERING_SCOPE: &str = "scope:governor";

/// Builds the canonical `RecordAuthorityFanoutState` transition from an
/// authenticated ingress and the exact post-fan-out owner snapshot.
///
/// The snapshot is serialized only after the Governor has validated it. The
/// Store receives those bytes as an opaque, digest-bound owner record and
/// arbitrates only `expected_owner_revision`; it never interprets authority or
/// derivative semantics.
pub fn authority_owner_state_envelope(
    ingress: &AuthorityOwnerStateIngress,
    snapshot: &AuthorityOwnerSnapshot,
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    ingress.validate()?;
    snapshot.validate()?;
    let fence = &ingress.identity.request.metadata.state_fence;
    if snapshot.state_fence != *fence {
        return Err(CompositionError::Provider(
            "authority owner-state snapshot is not bound to the authenticated fence".to_owned(),
        ));
    }
    let entries = generated_operation_manifests()
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let operation_manifest_digest: OperationManifestDigest =
        operation_manifest_set_digest(&entries)
            .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let snapshot_bytes = canonical_json_bytes(snapshot).map_err(|error| {
        CompositionError::Owner(format!("authority owner snapshot encoding failed: {error}"))
    })?;
    let snapshot_json = String::from_utf8(snapshot_bytes.clone()).map_err(|error| {
        CompositionError::Owner(format!(
            "authority owner snapshot is not UTF-8 JSON: {error}"
        ))
    })?;
    let snapshot_digest = sha256_hex(&snapshot_bytes);
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "owner_snapshot_json".to_owned(),
        serde_json::Value::String(snapshot_json),
    );
    parameters.insert(
        "owner_snapshot_digest".to_owned(),
        serde_json::Value::String(snapshot_digest.clone()),
    );
    parameters.insert(
        "expected_owner_revision".to_owned(),
        serde_json::Value::String(ingress.expected_owner_revision.to_string()),
    );
    let admission_contract_set_digest = sha256_hex(
        &canonical_json_bytes(&(
            &ingress.operation_id,
            ingress.identity.idempotency_key.as_str(),
            ingress.expected_owner_revision,
            &snapshot_digest,
            fence,
        ))
        .map_err(|error| CompositionError::Owner(error.to_string()))?,
    );
    let envelope = CanonicalWriteEnvelope {
        operation_id: ingress.operation_id.clone(),
        request: ingress.identity.request.metadata.clone(),
        idempotency_key: ingress.identity.idempotency_key.clone(),
        scope_id: ScopeId::new(AUTHORITY_OWNER_STATE_SCOPE_ID)
            .map_err(|error| CompositionError::Owner(error.to_string()))?,
        task_id: ingress
            .identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest,
        operation_manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordAuthorityFanoutState,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(AUTHORITY_OWNER_STATE_ORDERING_SCOPE)
                .map_err(|error| CompositionError::Owner(error.to_string()))?,
            expected_sequence: ingress.expected_ordering_sequence,
            state_fence: fence.clone(),
        }],
    };
    envelope
        .validate()
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    Ok(envelope)
}

/// Authority owner retaining only restored, pure authority state.
#[derive(Clone, Debug)]
pub struct AuthorityOwner {
    /// Exact Governor recovery fence retained with the restored authority state.
    state_fence: StateFence,
    /// Effect-level authorizer restored from its complete typed snapshot.
    pub effects: EffectAuthorizer,
    /// Grant graph lineage restored from its complete typed snapshot.
    pub grants: GrantGraph,
    /// Exact durable hydration registry restored with this owner.
    hydration_registry: Option<Vec<u8>>,
    /// Exact durable derivative fan-out state restored with this owner.
    revocation_fanout: Option<RevocationFanoutState>,
}

/// Restored authority owner with the exact history-suppressed set.
///
/// Returned by
/// [`AuthorityOwner::from_snapshot_with_revocation_history`]: the owner
/// never exposes a revoked origin or its dependent grants as effective,
/// and `suppressed` reports every history-suppressed grant with its
/// reason.
#[derive(Clone, Debug)]
pub struct AuthorityRestoreOutcome {
    /// Restored authority owner with revocations applied.
    pub owner: AuthorityOwner,
    /// Every history-suppressed grant in grant-id order with its reason.
    pub suppressed: Vec<SuppressedGrant>,
}

impl AuthorityOwner {
    pub(super) fn from_snapshot(
        snapshot: &AuthorityOwnerSnapshot,
        expected_fence: &StateFence,
    ) -> Result<Self, CompositionError> {
        snapshot.validate_against(expected_fence)?;
        let grants = GrantGraph::from_recovery_snapshot(snapshot.grant_graph.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let effects = EffectAuthorizer::from_snapshot(snapshot.effect_authorizer.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(Self {
            state_fence: snapshot.state_fence.clone(),
            effects,
            grants,
            hydration_registry: snapshot.hydration_registry.clone(),
            revocation_fanout: snapshot.revocation_fanout.clone(),
        })
    }

    /// Restores authority under explicit CURRENT revocation-history
    /// evidence, applying committed revocations before any grant becomes
    /// effective (issue #686).
    ///
    /// `None` history refuses: unavailable history is not absence of
    /// revocation and never restores as an empty closure. Stale (fence or
    /// revision drift, including drift against this snapshot's fence) and
    /// unknown (invalid, unordered, or non-revoked closure) evidence refuse
    /// likewise. A revoked origin and its dependent grants stay suppressed
    /// in the restored owner; unrelated valid grants restore exactly as the
    /// snapshot carries them, with the exact suppressed set reported.
    ///
    /// The legacy [`from_snapshot`](Self::from_snapshot) preserves its
    /// exact prior behavior for previously-admitted callers.
    pub fn from_snapshot_with_revocation_history(
        snapshot: &AuthorityOwnerSnapshot,
        expected_fence: &StateFence,
        history: Option<&RevocationHistoryEvidence>,
    ) -> Result<AuthorityRestoreOutcome, CompositionError> {
        snapshot.validate_against(expected_fence)?;
        let evidence = history.ok_or_else(|| {
            CompositionError::Recovery(
                "authority revocation history is unavailable; unavailable history is not absence of revocation"
                    .to_owned(),
            )
        })?;
        if evidence.state_fence != *expected_fence || evidence.state_fence != snapshot.state_fence {
            return Err(CompositionError::Recovery(
                "authority revocation history is stale for this recovery fence".to_owned(),
            ));
        }
        let outcome = GrantGraph::from_recovery_snapshot_with_revocation_history(
            snapshot.grant_graph.clone(),
            Some(evidence),
        )
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let mut effects = EffectAuthorizer::from_snapshot(snapshot.effect_authorizer.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        // I12.20: revoked lineage must not reactivate through restored
        // pending effects. Every history-suppressed grant (and its
        // suppressing closure) is a revoked root: current dependent
        // justifications/plans/pending effects are contested/reopened while
        // restored history stays immutable.
        let revoked_roots: BTreeSet<String> = outcome
            .suppressed
            .iter()
            .flat_map(|suppressed| [suppressed.grant_id.clone(), suppressed.closure_id.clone()])
            .collect();
        effects.contest_dependent_effects(&revoked_roots);
        effects.contest_current_claims(&revoked_roots);
        Ok(AuthorityRestoreOutcome {
            owner: Self {
                state_fence: snapshot.state_fence.clone(),
                effects,
                grants: outcome.graph,
                hydration_registry: snapshot.hydration_registry.clone(),
                revocation_fanout: snapshot.revocation_fanout.clone(),
            },
            suppressed: outcome.suppressed,
        })
    }

    /// Registers a current justification/plan/answer claim in the authority
    /// owner's revocation overlay.
    pub fn register_revocation_claim(
        &mut self,
        claim: eliot_authority::RevocationDependentClaim,
    ) -> Result<(), CompositionError> {
        self.effects
            .register_current_claim(claim)
            .map_err(|error| CompositionError::Owner(error.to_string()))
    }

    /// Returns current claim overlays for the production fan-out caller.
    #[must_use]
    pub fn revocation_claims(&self) -> Vec<eliot_authority::RevocationDependentClaim> {
        self.effects.current_claims()
    }

    /// Applies current effect and claim contest overlays for a committed
    /// revocation closure. Historical authorized records remain immutable.
    pub fn contest_effects_for_revocation(&mut self, revoked_roots: &BTreeSet<String>) -> usize {
        self.effects.contest_dependent_effects(revoked_roots)
            + self.effects.contest_current_claims(revoked_roots)
    }

    /// Replaces the exact durable hydration registry after its producer has
    /// persisted and validated the owner image. The bytes are opaque to the
    /// authority owner; the closure provider revalidates them on restoration.
    pub fn set_hydration_registry(
        &mut self,
        bytes: Option<Vec<u8>>,
    ) -> Result<(), CompositionError> {
        if bytes
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 4 * 1024 * 1024)
        {
            return Err(CompositionError::Recovery(
                "authority owner hydration registry is empty or exceeds its bound".to_owned(),
            ));
        }
        self.hydration_registry = bytes;
        Ok(())
    }

    /// Returns the exact durable hydration registry bytes, if one was
    /// recovered. Consumers must import and validate them before serving.
    #[must_use]
    pub fn hydration_registry(&self) -> Option<&[u8]> {
        self.hydration_registry.as_deref()
    }

    /// Returns the durable derivative fan-out state, if one has been
    /// committed. Consumers must use this state rather than rebuilding it from
    /// a synthetic context.
    #[must_use]
    pub fn revocation_fanout(&self) -> Option<&RevocationFanoutState> {
        self.revocation_fanout.as_ref()
    }

    /// Installs a validated durable fan-out state on the real Authority owner.
    pub fn set_revocation_fanout(
        &mut self,
        state: RevocationFanoutState,
    ) -> Result<(), CompositionError> {
        state.validate()?;
        if state.state_fence != self.state_fence {
            return Err(CompositionError::Recovery(
                "revocation fan-out state is bound to a different authority fence".to_owned(),
            ));
        }
        self.revocation_fanout = Some(state);
        Ok(())
    }

    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Emits the complete deterministic typed authority recovery payload.
    pub fn snapshot(&self) -> Result<AuthorityOwnerSnapshot, CompositionError> {
        let grant_graph = self
            .grants
            .recovery_snapshot()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let effect_authorizer = self
            .effects
            .snapshot()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        AuthorityOwnerSnapshot::with_recovery_state(
            self.state_fence.clone(),
            grant_graph,
            effect_authorizer,
            self.hydration_registry.clone(),
            self.revocation_fanout.clone(),
        )
    }
}

/// Exact authority request presented to the P-07 boundary, retained alongside
/// its owner snapshot until exact reconciliation. The snapshot alone is not an
/// operation identity: only the retained request identifies the presented
/// operation when an acknowledgement is lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PresentedAuthorityRequest {
    GrantActivation(GrantActivationRequest),
    GrantRevocation(GrantRevocationRequest),
    IntroductionActivation(IntroductionActivationRequest),
    IntroductionRevocation(IntroductionRevocationRequest),
}

impl PresentedAuthorityRequest {
    /// Returns the snapshot this presentation was compiled against.
    #[must_use]
    pub fn snapshot_id(&self) -> &SnapshotId {
        match self {
            Self::GrantActivation(request) => &request.snapshot_id,
            Self::GrantRevocation(request) => &request.snapshot_id,
            Self::IntroductionActivation(request) => &request.snapshot_id,
            Self::IntroductionRevocation(request) => &request.snapshot_id,
        }
    }

    /// Returns the authority binding carried by this presentation.
    #[must_use]
    pub fn binding(&self) -> &AuthorityBinding {
        match self {
            Self::GrantActivation(request) => &request.binding,
            Self::GrantRevocation(request) => &request.binding,
            Self::IntroductionActivation(request) => &request.binding,
            Self::IntroductionRevocation(request) => &request.binding,
        }
    }

    /// Returns the retention-ledger key, namespacing grants from introductions
    /// so one identity can never alias the other family.
    #[must_use]
    pub fn ledger_key(&self) -> String {
        match self {
            Self::GrantActivation(request) => format!("grant:{}", request.grant_id),
            Self::GrantRevocation(request) => format!("grant:{}", request.grant_id),
            Self::IntroductionActivation(request) => {
                format!("introduction:{}", request.introduction_id)
            }
            Self::IntroductionRevocation(request) => {
                format!("introduction:{}", request.introduction_id)
            }
        }
    }

    const fn is_activation(&self) -> bool {
        matches!(
            self,
            Self::GrantActivation(_) | Self::IntroductionActivation(_)
        )
    }
}

/// Receipt-driven reconciliation state of one retained presentation. Unknown
/// outcomes stay pending until the exact receipt reconciles them. Revocation
/// intent is strictly stronger than any active right and survives a failed
/// canonical reconciliation; nothing here can report active authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityPresentationState {
    Pending,
    UnknownOutcome,
    Active { activation_id: String },
    RevocationIntended,
    Revoked { revocation_id: String },
}

/// Exact presented request retained with the owner snapshot that produced its
/// mechanical projection, plus the receipt-driven reconciliation state.
///
/// Pure record: it files Kernel-issued receipts and revocation intent, never
/// mints authority. Only a validated `Active` receipt moves a presentation to
/// `Active`; only a validated terminal revocation receipt moves it to
/// `Revoked`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedAuthorityRequest {
    request: PresentedAuthorityRequest,
    snapshot: AuthorityOwnerSnapshot,
    state: AuthorityPresentationState,
}

impl RetainedAuthorityRequest {
    /// Retains one exact presentation against the snapshot it was compiled
    /// from. A presentation bound to another fence fails closed here, before
    /// any transport is touched.
    pub fn retain(
        request: PresentedAuthorityRequest,
        snapshot: AuthorityOwnerSnapshot,
    ) -> Result<Self, CompositionError> {
        snapshot.validate()?;
        if request.binding().state_fence != snapshot.state_fence {
            return Err(CompositionError::Recovery(
                "authority presentation is not bound to the retained owner fence".to_owned(),
            ));
        }
        Ok(Self {
            request,
            snapshot,
            state: AuthorityPresentationState::Pending,
        })
    }

    /// Returns the exact retained request.
    #[must_use]
    pub const fn request(&self) -> &PresentedAuthorityRequest {
        &self.request
    }

    /// Returns the owner snapshot the presentation was compiled from.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthorityOwnerSnapshot {
        &self.snapshot
    }

    /// Returns the current receipt-driven reconciliation state.
    #[must_use]
    pub const fn state(&self) -> &AuthorityPresentationState {
        &self.state
    }

    /// Records a lost acknowledgement for the exact presented snapshot. Any
    /// other snapshot fails closed: it cannot reconcile this presentation.
    pub fn note_unknown_outcome(
        &mut self,
        snapshot_id: &SnapshotId,
    ) -> Result<(), CompositionError> {
        if self.request.snapshot_id() != snapshot_id {
            return Err(CompositionError::Recovery(
                "unknown P-07 outcome names a different snapshot than the retained request"
                    .to_owned(),
            ));
        }
        match self.state {
            AuthorityPresentationState::Pending | AuthorityPresentationState::UnknownOutcome => {
                self.state = AuthorityPresentationState::UnknownOutcome;
                Ok(())
            }
            _ => Err(CompositionError::Authority(P07PortError::InvalidBinding)),
        }
    }

    /// Records a validated `Active` receipt for the exact presented snapshot.
    /// A second activation on a recorded identity fails closed instead of
    /// issuing twice; a receipt bound to another snapshot or epoch fails
    /// closed without touching the retained state.
    pub fn note_activated(
        &mut self,
        receipt: &AuthorityActivationReceipt,
    ) -> Result<(), CompositionError> {
        if !self.request.is_activation() {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        }
        self.check_receipt_binding(&receipt.snapshot_id, &receipt.authority_epoch)?;
        receipt
            .validate()
            .map_err(|_| CompositionError::Authority(P07PortError::InvalidBinding))?;
        match self.state {
            AuthorityPresentationState::Pending | AuthorityPresentationState::UnknownOutcome => {
                self.state = AuthorityPresentationState::Active {
                    activation_id: receipt.activation_id.clone(),
                };
                Ok(())
            }
            _ => Err(CompositionError::Authority(P07PortError::InvalidBinding)),
        }
    }

    /// Records that Kernel revoked first while canonical reconciliation did
    /// not complete. This wipes any live reading and strictly blocks effects;
    /// it never reports an active right.
    pub fn note_revocation_intended(&mut self) {
        self.state = AuthorityPresentationState::RevocationIntended;
    }

    /// Records a validated terminal revocation receipt for the exact presented
    /// snapshot. A receipt bound to another snapshot or epoch fails closed.
    pub fn note_revoked(
        &mut self,
        receipt: &AuthorityRevocationReceipt,
    ) -> Result<(), CompositionError> {
        self.check_receipt_binding(&receipt.snapshot_id, &receipt.authority_epoch)?;
        receipt
            .validate()
            .map_err(|_| CompositionError::Authority(P07PortError::InvalidBinding))?;
        self.state = AuthorityPresentationState::Revoked {
            revocation_id: receipt.revocation_id.clone(),
        };
        Ok(())
    }

    /// Composes the retained receipt-driven state over the recovered graph
    /// status. A validated receipt is the only path to `Active`; revocation
    /// intent composes to `Revoked`; anything unresolved keeps the recovered
    /// status (defaulting to `PendingActivation` when the graph carries no
    /// record, so an unproven grant is never read as effective).
    #[must_use]
    pub fn grant_status(&self, graph_status: Option<GrantStatus>) -> GrantStatus {
        match &self.state {
            AuthorityPresentationState::Active { .. } => GrantStatus::Active,
            AuthorityPresentationState::RevocationIntended
            | AuthorityPresentationState::Revoked { .. } => GrantStatus::Revoked,
            AuthorityPresentationState::Pending | AuthorityPresentationState::UnknownOutcome => {
                graph_status.unwrap_or(GrantStatus::PendingActivation)
            }
        }
    }

    /// Projects the retained state for an introduction. Introductions have no
    /// recovered graph fallback: only a validated receipt reports `Active`,
    /// revocation intent reports `Revoked`, and anything unresolved reports
    /// nothing (never an effective right).
    #[must_use]
    pub const fn introduction_status(&self) -> Option<IntroductionStatus> {
        match self.state {
            AuthorityPresentationState::Active { .. } => Some(IntroductionStatus::Active),
            AuthorityPresentationState::RevocationIntended
            | AuthorityPresentationState::Revoked { .. } => Some(IntroductionStatus::Revoked),
            AuthorityPresentationState::Pending | AuthorityPresentationState::UnknownOutcome => {
                None
            }
        }
    }

    fn check_receipt_binding(
        &self,
        receipt_snapshot_id: &str,
        receipt_epoch: &EpochId,
    ) -> Result<(), CompositionError> {
        if receipt_snapshot_id != self.request.snapshot_id().as_str() {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        }
        if !receipt_epoch.is_same_authority(&self.snapshot.state_fence.authority_epoch) {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        }
        Ok(())
    }
}
