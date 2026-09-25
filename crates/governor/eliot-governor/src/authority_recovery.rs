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
use crate::owner_closure_provider::AdmittedHydrationsSnapshot;
use eliot_authority::{
    EffectAuthorizer, EffectAuthorizerRecoverySnapshot, GrantActivationRequest, GrantGraph,
    GrantGraphRecoverySnapshot, GrantRevocationRequest, GrantStatus, IntroductionActivationRequest,
    IntroductionRevocationRequest, IntroductionStatus, P07PortError, RevocationHistoryEvidence,
    SnapshotId, SuppressedGrant,
};
use eliot_contracts::{EpochId, StateFence};
use eliot_receipts::AuthorityBinding;
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Versioned semantic owner payload retained by Governor recovery.
pub const AUTHORITY_OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.authority-owner.v2";
pub const AUTHORITY_OWNER_SNAPSHOT_VERSION: u16 = 2;
const LEGACY_AUTHORITY_OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.authority-owner.v1";
const LEGACY_AUTHORITY_OWNER_SNAPSHOT_VERSION: u16 = 1;

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
    /// Versioned exact grant/introduction hydration registry admitted at the
    /// same fence and graph revision. `None` is an explicit legacy/unavailable
    /// projection: the daemon may recover its other owners, but the P-07 owner
    /// feed remains closed until canonical hydrations are supplied.
    pub owner_hydrations: Option<AdmittedHydrationsSnapshot>,
}

impl AuthorityOwnerSnapshot {
    /// Constructs a typed payload with an empty closure-hydration registry.
    ///
    /// This constructor remains valid for owner payloads that contain no
    /// grant graph. Any non-empty owner restored into the production closure
    /// feed must use [`Self::new_with_owner_hydrations`] so no hydration is
    /// silently replaced by process-local absence.
    pub fn new(
        state_fence: StateFence,
        grant_graph: GrantGraphRecoverySnapshot,
        effect_authorizer: EffectAuthorizerRecoverySnapshot,
    ) -> Result<Self, CompositionError> {
        if !grant_graph.grants.is_empty() {
            return Err(CompositionError::Recovery(
                "non-empty authority owner snapshots require explicit owner hydrations".to_owned(),
            ));
        }
        let owner_hydrations =
            AdmittedHydrationsSnapshot::empty(state_fence.clone(), grant_graph.revision)?;
        Self::new_with_owner_hydrations(
            state_fence,
            grant_graph,
            effect_authorizer,
            owner_hydrations,
        )
    }

    /// Constructs the canonical authority-owner payload with the exact
    /// versioned closure hydration registry admitted at the same graph
    /// revision and State Fence.
    pub fn new_with_owner_hydrations(
        state_fence: StateFence,
        grant_graph: GrantGraphRecoverySnapshot,
        effect_authorizer: EffectAuthorizerRecoverySnapshot,
        owner_hydrations: AdmittedHydrationsSnapshot,
    ) -> Result<Self, CompositionError> {
        let snapshot = Self {
            schema: AUTHORITY_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: AUTHORITY_OWNER_SNAPSHOT_VERSION,
            state_fence,
            grant_graph,
            effect_authorizer,
            owner_hydrations: Some(owner_hydrations),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Rehydrates the canonical owner parts from one durable owner payload.
    ///
    /// This is the production constructor seam for a v2 payload. The
    /// hydration registry is supplied by the durable owner record; it is never
    /// replaced with an empty registry when the graph contains live lineage.
    pub fn from_durable_owner_payload(
        state_fence: StateFence,
        grant_graph: GrantGraphRecoverySnapshot,
        effect_authorizer: EffectAuthorizerRecoverySnapshot,
        owner_hydrations: AdmittedHydrationsSnapshot,
    ) -> Result<Self, CompositionError> {
        Self::new_with_owner_hydrations(
            state_fence,
            grant_graph,
            effect_authorizer,
            owner_hydrations,
        )
    }

    /// Re-runs the v2 constructor for a decoded durable payload before the
    /// semantic owner is built. Legacy payloads remain explicit unavailable
    /// projections and are never promoted into a populated registry.
    fn canonical_durable_snapshot(snapshot: &Self) -> Result<Self, CompositionError> {
        let Some(owner_hydrations) = snapshot.owner_hydrations.clone() else {
            return Ok(snapshot.clone());
        };
        Self::from_durable_owner_payload(
            snapshot.state_fence.clone(),
            snapshot.grant_graph.clone(),
            snapshot.effect_authorizer.clone(),
            owner_hydrations,
        )
    }

    /// Validates schema, semantic authority state, and exact nested fences.
    #[allow(
        clippy::too_many_lines,
        reason = "owner recovery keeps schema, graph, hydration, and fence contours in one fail-closed validator"
    )]
    pub fn validate(&self) -> Result<(), CompositionError> {
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let current_schema = self.schema == AUTHORITY_OWNER_SNAPSHOT_SCHEMA
            && self.version == AUTHORITY_OWNER_SNAPSHOT_VERSION;
        // A v1 owner record may still recover unrelated Governor owners, but
        // its absent closure registry is an explicit unavailable marker. The
        // P-07 feed refuses it; it is never treated as an empty registry.
        let legacy_schema = self.schema == LEGACY_AUTHORITY_OWNER_SNAPSHOT_SCHEMA
            && self.version == LEGACY_AUTHORITY_OWNER_SNAPSHOT_VERSION
            && self.owner_hydrations.is_none();
        if !current_schema && !legacy_schema {
            return Err(CompositionError::Recovery(
                "authority owner snapshot has an invalid schema or version".to_owned(),
            ));
        }
        if legacy_schema && !self.grant_graph.grants.is_empty() {
            return Err(CompositionError::Recovery(
                "legacy authority owner payload cannot restore non-empty grant lineage without a v2 hydration registry"
                    .to_owned(),
            ));
        }
        self.grant_graph
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        self.effect_authorizer
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let has_hydration_entries =
            self.owner_hydrations
                .as_ref()
                .is_some_and(|owner_hydrations| {
                    !owner_hydrations.members.is_empty() || !owner_hydrations.roots.is_empty()
                });
        if !self.grant_graph.grants.is_empty() && !has_hydration_entries {
            return Err(CompositionError::Recovery(
                "non-empty authority owner requires explicit grant hydrations".to_owned(),
            ));
        }
        if let Some(owner_hydrations) = &self.owner_hydrations {
            owner_hydrations
                .validate_shape()
                .map_err(|error| CompositionError::Recovery(error.to_string()))?;
            if owner_hydrations.state_fence != self.state_fence
                || owner_hydrations.grant_graph_revision != self.grant_graph.revision
            {
                return Err(CompositionError::Recovery(
                    "authority owner hydration registry has a stale fence or graph revision"
                        .to_owned(),
                ));
            }
            let mut hydration_grants = BTreeSet::new();
            macro_rules! validate_grant_hydration {
                ($hydration:expr, $is_root:expr) => {{
                    let hydration = $hydration;
                    let intent = &hydration.intent;
                    if intent.grant_graph_revision != self.grant_graph.revision
                        || intent.binding.state_fence != self.state_fence
                    {
                        return Err(CompositionError::Recovery(
                            "authority owner hydration entry has a mixed graph revision or fence"
                                .to_owned(),
                        ));
                    }
                    if !hydration_grants.insert(intent.grant_id.clone()) {
                        return Err(CompositionError::Recovery(
                            "authority owner hydration registry contains a duplicate grant identity"
                                .to_owned(),
                        ));
                    }
                    let Some(record) = self
                        .grant_graph
                        .grants
                        .iter()
                        .find(|grant| grant.grant_id == intent.grant_id)
                    else {
                        return Err(CompositionError::Recovery(
                            "authority owner hydration names a grant outside the durable graph"
                                .to_owned(),
                        ));
                    };
                    if record.authority_root_ref != intent.authority_root_ref
                        || record.parent_grant_id.as_deref() != intent.parent_grant_id.as_deref()
                        || record.binding != intent.binding
                        || (($is_root) && intent.parent_grant_id.is_some())
                        || (!($is_root) && intent.parent_grant_id.is_none())
                    {
                        return Err(CompositionError::Recovery(
                            "authority owner hydration entry disagrees with its durable graph lineage"
                                .to_owned(),
                        ));
                    }
                }};
            }
            for member in &owner_hydrations.members {
                validate_grant_hydration!(member, false);
            }
            for root in &owner_hydrations.roots {
                validate_grant_hydration!(root, true);
            }
            for hydration in &owner_hydrations.introductions {
                let intent = &hydration.intent;
                if intent.grant_graph_revision != self.grant_graph.revision
                    || intent.binding.state_fence != self.state_fence
                {
                    return Err(CompositionError::Recovery(
                        "authority owner introduction has a mixed graph revision or fence"
                            .to_owned(),
                    ));
                }
                for supporting_grant_id in &intent.supporting_grant_ids {
                    let Some(record) = self
                        .grant_graph
                        .grants
                        .iter()
                        .find(|grant| grant.grant_id == *supporting_grant_id)
                    else {
                        return Err(CompositionError::Recovery(
                            "authority owner introduction names an unknown supporting grant"
                                .to_owned(),
                        ));
                    };
                    if record.authority_root_ref != intent.authority_root_ref {
                        return Err(CompositionError::Recovery(
                            "authority owner introduction crosses authority roots".to_owned(),
                        ));
                    }
                }
            }
            for (target, survivors) in &owner_hydrations.preserved {
                let Some(target_record) = self
                    .grant_graph
                    .grants
                    .iter()
                    .find(|grant| grant.grant_id == *target)
                else {
                    return Err(CompositionError::Recovery(
                        "authority owner preserved path names an unknown target".to_owned(),
                    ));
                };
                for survivor in survivors {
                    let Some(descendant) = self
                        .grant_graph
                        .grants
                        .iter()
                        .find(|grant| grant.grant_id == survivor.grant_id)
                    else {
                        return Err(CompositionError::Recovery(
                            "authority owner preserved path names an unknown descendant".to_owned(),
                        ));
                    };
                    let Some(covering) = self
                        .grant_graph
                        .grants
                        .iter()
                        .find(|grant| grant.grant_id == survivor.covering_grant_id)
                    else {
                        return Err(CompositionError::Recovery(
                            "authority owner preserved path names an unknown cover".to_owned(),
                        ));
                    };
                    if descendant.authority_root_ref != target_record.authority_root_ref
                        || covering.authority_root_ref != survivor.covering_root_ref
                    {
                        return Err(CompositionError::Recovery(
                            "authority owner preserved path crosses authority roots".to_owned(),
                        ));
                    }
                }
            }
        }
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
    /// Exact closure hydration registry carried by the canonical owner
    /// snapshot, or an explicit legacy-unavailable marker. It is data, not a
    /// second graph owner.
    pub(crate) owner_hydrations: Option<AdmittedHydrationsSnapshot>,
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
        let snapshot = AuthorityOwnerSnapshot::canonical_durable_snapshot(snapshot)?;
        snapshot.validate_against(expected_fence)?;
        let grants = GrantGraph::from_recovery_snapshot(snapshot.grant_graph.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let effects = EffectAuthorizer::from_snapshot(snapshot.effect_authorizer.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(Self {
            state_fence: snapshot.state_fence.clone(),
            effects,
            grants,
            owner_hydrations: snapshot.owner_hydrations.clone(),
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
        let snapshot = AuthorityOwnerSnapshot::canonical_durable_snapshot(snapshot)?;
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
        if evidence.source_revision != snapshot.grant_graph.revision {
            return Err(CompositionError::Recovery(
                "authority revocation history revision disagrees with the owner graph".to_owned(),
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
        Ok(AuthorityRestoreOutcome {
            owner: Self {
                state_fence: snapshot.state_fence.clone(),
                effects,
                grants: outcome.graph,
                owner_hydrations: snapshot.owner_hydrations.clone(),
            },
            suppressed: outcome.suppressed,
        })
    }

    /// Returns the exact fence retained by this authority owner.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    pub(crate) fn invalidate_owner_hydrations(&mut self) {
        self.owner_hydrations = None;
    }

    pub(crate) fn replace_owner_hydrations(
        &mut self,
        owner_hydrations: AdmittedHydrationsSnapshot,
    ) {
        debug_assert_eq!(owner_hydrations.state_fence, self.state_fence);
        debug_assert_eq!(
            owner_hydrations.grant_graph_revision,
            self.grants.revision()
        );
        self.owner_hydrations = Some(owner_hydrations);
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
        let snapshot = AuthorityOwnerSnapshot {
            schema: AUTHORITY_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: AUTHORITY_OWNER_SNAPSHOT_VERSION,
            state_fence: self.state_fence.clone(),
            grant_graph,
            effect_authorizer,
            owner_hydrations: self.owner_hydrations.clone(),
        };
        snapshot.validate()?;
        Ok(snapshot)
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
