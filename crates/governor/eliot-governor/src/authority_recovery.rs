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
use eliot_authority::{
    EffectAuthorizer, EffectAuthorizerRecoverySnapshot, GrantActivationRequest, GrantGraph,
    GrantGraphRecoverySnapshot, GrantRevocationRequest, GrantStatus, IntroductionActivationRequest,
    IntroductionRevocationRequest, IntroductionStatus, P07PortError, SnapshotId,
};
use eliot_contracts::{EpochId, StateFence};
use eliot_receipts::AuthorityBinding;
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
}

impl AuthorityOwnerSnapshot {
    /// Constructs a typed payload after validating both authority snapshots.
    pub fn new(
        state_fence: StateFence,
        grant_graph: GrantGraphRecoverySnapshot,
        effect_authorizer: EffectAuthorizerRecoverySnapshot,
    ) -> Result<Self, CompositionError> {
        let snapshot = Self {
            schema: AUTHORITY_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: AUTHORITY_OWNER_SNAPSHOT_VERSION,
            state_fence,
            grant_graph,
            effect_authorizer,
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

/// Authority owner retaining only restored, pure authority state.
#[derive(Clone, Debug)]
pub struct AuthorityOwner {
    /// Exact Governor recovery fence retained with the restored authority state.
    state_fence: StateFence,
    /// Effect-level authorizer restored from its complete typed snapshot.
    pub effects: EffectAuthorizer,
    /// Grant graph lineage restored from its complete typed snapshot.
    pub grants: GrantGraph,
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
        })
    }

    /// Returns the exact fence retained by this authority owner.
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
        AuthorityOwnerSnapshot::new(self.state_fence.clone(), grant_graph, effect_authorizer)
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
