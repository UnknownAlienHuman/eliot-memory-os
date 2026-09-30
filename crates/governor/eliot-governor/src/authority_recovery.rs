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
    AuthorityError, AuthorizedEffectRecoveryRecord, DependentEffectState, EffectAuthorizer,
    EffectAuthorizerRecoverySnapshot, EffectOutcome, GRANT_GRAPH_RECOVERY_SCHEMA,
    GrantActivationRequest, GrantGraph, GrantGraphRecoverySnapshot, GrantRevocationRequest,
    GrantStatus, IntroductionActivationRequest, IntroductionRevocationRequest, IntroductionStatus,
    LEGACY_GRANT_GRAPH_RECOVERY_VERSION, P07PortError, ReceiptObligation,
    RevocationHistoryEvidence, RevocationOperationIdentity, RootTransitionActivationReceipt,
    RootTransitionActivationRequest, SnapshotId, SuppressedGrant,
};
use eliot_contracts::{EpochId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_receipts::{AuthorityBinding, EffectClass};
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Versioned semantic owner payload retained by Governor recovery.
///
/// #2962 step 11: the enclosing payload moved to v3 because accepting grant-graph
/// v2 changes the outer canonical preimage and the compatibility meaning of
/// the embedded `grant_graph` section. Old v2 bytes are never silently
/// reinterpreted as v3; they take the closed [`GrantGraphLegacyMigration`]
/// path instead.
pub const AUTHORITY_OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.authority-owner.v3";
pub const AUTHORITY_OWNER_SNAPSHOT_VERSION: u16 = 3;
const LEGACY_AUTHORITY_OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.authority-owner.v2";
const LEGACY_AUTHORITY_OWNER_SNAPSHOT_VERSION: u16 = 2;
const OLDEST_AUTHORITY_OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.authority-owner.v1";
const OLDEST_AUTHORITY_OWNER_SNAPSHOT_VERSION: u16 = 1;

/// Nested version dispatch for the embedded grant-graph contract (issue #2962,
/// step 9).
///
/// The graph schema AND version are decided before any protected field is
/// interpreted, so a legacy payload — whose `root_transitions` carried only
/// self-agreeing structural fields — can never be read under current
/// authenticated-transition semantics, and its absent transition/quarantine
/// sections are never treated as "no crossings recorded".
fn require_current_grant_graph_contract(
    grant_graph: &GrantGraphRecoverySnapshot,
) -> Result<(), CompositionError> {
    let version = GrantGraph::recovery_contract_version(grant_graph);
    if grant_graph.schema != GRANT_GRAPH_RECOVERY_SCHEMA {
        return Err(CompositionError::Recovery(
            "authority owner grant graph has an unsupported schema identity".to_owned(),
        ));
    }
    if version != eliot_authority::GRANT_GRAPH_RECOVERY_VERSION {
        return Err(CompositionError::Recovery(format!(
            "authority owner grant graph declares legacy contract version {version}; \
             legacy cross-root data is inert/quarantined and cannot be restored as authority"
        )));
    }
    Ok(())
}

/// One legacy (v1) grant-graph payload plus the digest of the exact bytes it
/// was read from.
///
/// The bytes are preserved, not rewritten: a v1 cross-root entry becomes inert
/// evidence under v2 restore, and this record proves for audit WHICH original
/// bytes were migrated and what the migration decided. Obtaining active
/// authority for a legacy crossing requires a NEW explicit v2 verification and
/// activation operation — never an in-place historical rewrite.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantGraphLegacyMigration {
    /// Declared contract version of the migrated payload.
    pub from_version: u16,
    /// Canonical digest of the exact original v1 record bytes.
    pub original_record_sha256: String,
    /// Cross-root edges the v1 payload named, in parent/child order.
    pub legacy_cross_root_edges: Vec<LegacyCrossRootEdgeRecord>,
    /// Fixed migration disposition: every legacy crossing is unqualified.
    pub disposition: LegacyGrantGraphDisposition,
    /// Closed migration schema identity.
    pub schema: String,
    /// Closed migration schema version.
    pub version: u16,
}

/// One legacy cross-root edge retained for audit under the migration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacyCrossRootEdgeRecord {
    /// Crossing source grant identity.
    pub parent_grant: String,
    /// Crossing dependent grant identity.
    pub child_grant: String,
    /// Legacy transition identity, retained verbatim for audit.
    pub legacy_transition: String,
}

/// The only disposition a legacy v1 grant-graph payload may take.
///
/// `InertQuarantined` is total and unconditional: a v1 `root_transitions`
/// entry does not become active authority merely because its copied fields
/// agree with the live grants, because v1 never carried an operation identity,
/// a canonical request digest, grant commitments, or mechanical activation
/// evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LegacyGrantGraphDisposition {
    InertQuarantined,
}

/// Closed schema identity of the legacy grant-graph migration record.
pub const GRANT_GRAPH_LEGACY_MIGRATION_SCHEMA: &str = "eliot.governor.grant-graph-legacy-migration";
/// Closed schema version of the legacy grant-graph migration record.
pub const GRANT_GRAPH_LEGACY_MIGRATION_VERSION: u16 = 1;

impl GrantGraphLegacyMigration {
    /// Builds the migration record for one decoded v1 payload.
    ///
    /// The digest is computed over the decoded value's canonical bytes, which
    /// is the exact v1 contract shape, so the retained digest identifies the
    /// migrated record rather than any ELIOT-authored reinterpretation of it.
    pub fn from_legacy_v1(snapshot: &GrantGraphRecoverySnapshot) -> Result<Self, CompositionError> {
        let bytes = canonical_json_bytes(snapshot).map_err(|error| {
            CompositionError::Recovery(format!(
                "legacy grant graph could not be canonicalized for audit: {error}"
            ))
        })?;
        Ok(Self {
            from_version: snapshot.version,
            original_record_sha256: sha256_hex(&bytes),
            legacy_cross_root_edges: Vec::new(),
            disposition: LegacyGrantGraphDisposition::InertQuarantined,
            schema: GRANT_GRAPH_LEGACY_MIGRATION_SCHEMA.to_owned(),
            version: GRANT_GRAPH_LEGACY_MIGRATION_VERSION,
        })
    }

    /// Validates the closed migration shape.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] for a foreign schema/version, a
    /// from-version that is not the legacy version, or any disposition other
    /// than the one inert migration permits.
    pub fn validate(&self) -> Result<(), CompositionError> {
        if self.schema != GRANT_GRAPH_LEGACY_MIGRATION_SCHEMA
            || self.version != GRANT_GRAPH_LEGACY_MIGRATION_VERSION
        {
            return Err(CompositionError::Recovery(
                "grant graph legacy migration record has an invalid schema or version".to_owned(),
            ));
        }
        if self.from_version != LEGACY_GRANT_GRAPH_RECOVERY_VERSION {
            return Err(CompositionError::Recovery(
                "grant graph legacy migration record does not name the legacy graph version"
                    .to_owned(),
            ));
        }
        if self.disposition != LegacyGrantGraphDisposition::InertQuarantined {
            return Err(CompositionError::Recovery(
                "legacy grant graph cannot migrate to anything but inert quarantined evidence"
                    .to_owned(),
            ));
        }
        if self.original_record_sha256.len() != 64 {
            return Err(CompositionError::Recovery(
                "grant graph legacy migration record has a malformed original digest".to_owned(),
            ));
        }
        Ok(())
    }
}

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
    /// Closed record of a deliberate legacy (v1 grant-graph) migration, with
    /// the exact original record digest and the inert disposition. `None` is
    /// the normal case for a payload that never migrated; it is never
    /// synthesized to excuse an absent legacy section.
    pub legacy_grant_graph_migration: Option<GrantGraphLegacyMigration>,
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
        Self::new_with_owner_hydrations_and_migration(
            state_fence,
            grant_graph,
            effect_authorizer,
            owner_hydrations,
            None,
        )
    }

    /// Constructs the canonical authority-owner payload, optionally carrying a
    /// closed record of a deliberate legacy grant-graph migration.
    ///
    /// #2962 step 10/11: a migrated payload is admitted only when it declares
    /// the CURRENT grant-graph contract version and presents its migration
    /// record. A payload still carrying a legacy (v1) grant-graph section is
    /// refused here rather than silently upgraded, so old outer-v2 bytes can
    /// never acquire stronger nested authority semantics by passing through
    /// this constructor.
    pub fn new_with_owner_hydrations_and_migration(
        state_fence: StateFence,
        grant_graph: GrantGraphRecoverySnapshot,
        effect_authorizer: EffectAuthorizerRecoverySnapshot,
        owner_hydrations: AdmittedHydrationsSnapshot,
        legacy_grant_graph_migration: Option<GrantGraphLegacyMigration>,
    ) -> Result<Self, CompositionError> {
        require_current_grant_graph_contract(&grant_graph)?;
        if let Some(migration) = &legacy_grant_graph_migration {
            migration.validate()?;
        }
        let snapshot = Self {
            schema: AUTHORITY_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: AUTHORITY_OWNER_SNAPSHOT_VERSION,
            state_fence,
            grant_graph,
            effect_authorizer,
            owner_hydrations: Some(owner_hydrations),
            legacy_grant_graph_migration,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Rehydrates the canonical owner parts from one durable owner payload.
    ///
    /// This is the production constructor seam for a current payload. The
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

    /// Re-runs the current constructor for a decoded durable payload before
    /// the semantic owner is built. Legacy payloads remain explicit unavailable
    /// projections and are never promoted into a populated registry.
    fn canonical_durable_snapshot(snapshot: &Self) -> Result<Self, CompositionError> {
        let Some(owner_hydrations) = snapshot.owner_hydrations.clone() else {
            return Ok(snapshot.clone());
        };
        Self::new_with_owner_hydrations_and_migration(
            snapshot.state_fence.clone(),
            snapshot.grant_graph.clone(),
            snapshot.effect_authorizer.clone(),
            owner_hydrations,
            snapshot.legacy_grant_graph_migration.clone(),
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
        // A pre-current owner record may still recover unrelated Governor
        // owners, but its absent closure registry is an explicit unavailable
        // marker. The P-07 feed refuses it; it is never treated as an empty
        // registry. Two legacy schemas are distinguished because only the
        // v2-shaped one carries a hydration registry.
        let legacy_schema = (self.schema == LEGACY_AUTHORITY_OWNER_SNAPSHOT_SCHEMA
            && self.version == LEGACY_AUTHORITY_OWNER_SNAPSHOT_VERSION
            && self.owner_hydrations.is_none())
            || (self.schema == OLDEST_AUTHORITY_OWNER_SNAPSHOT_SCHEMA
                && self.version == OLDEST_AUTHORITY_OWNER_SNAPSHOT_VERSION
                && self.owner_hydrations.is_none());
        if !current_schema && !legacy_schema {
            return Err(CompositionError::Recovery(
                "authority owner snapshot has an invalid schema or version".to_owned(),
            ));
        }
        if legacy_schema && !self.grant_graph.grants.is_empty() {
            return Err(CompositionError::Recovery(
                "legacy authority owner payload cannot restore non-empty grant lineage without a current hydration registry"
                    .to_owned(),
            ));
        }
        if let Some(migration) = &self.legacy_grant_graph_migration {
            migration.validate()?;
        }
        // Nested dispatch: the grant-graph contract version is decided before
        // any of its protected sections is interpreted, so a legacy payload
        // refuses by its own version rather than being read under current
        // semantics with absent authority-sensitive fields.
        require_current_grant_graph_contract(&self.grant_graph)?;
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
    /// Recovery-side effect obligations rebuilt from the restored
    /// authorization ledger (issue #1793 seq 6). Keyed by idempotency
    /// identity so expiry or loss of a local queue entry never releases
    /// them; only reconcile-by-identity retires one. Rebuilt by
    /// [`AuthorityOwner::rebuild_effect_obligations`] after restore and
    /// before dependent dispatch. Not part of the versioned snapshot wire
    /// contract: dispatch/observation transitions observed in this
    /// generation are owner-retained until the durable owner write path
    /// persists them.
    effect_obligations: BTreeMap<String, RetainedEffectObligation>,
    /// Durable revocation-history source revision applied by the latest
    /// history-bound restore (`None` when restored without CURRENT history
    /// evidence). Read back via
    /// [`AuthorityOwner::authority_applicability`]; it is lineage, not a
    /// second revocation store.
    last_revocation_source_revision: Option<u64>,
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
        let grants = GrantGraph::from_recovery_snapshot(&snapshot.grant_graph)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let effects = EffectAuthorizer::from_snapshot(snapshot.effect_authorizer.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(Self {
            state_fence: snapshot.state_fence.clone(),
            effects,
            grants,
            owner_hydrations: snapshot.owner_hydrations.clone(),
            effect_obligations: BTreeMap::new(),
            last_revocation_source_revision: None,
        })
    }

    /// Restores authority under explicit CURRENT revocation-history
    /// evidence, applying committed revocations before any grant becomes
    /// effective (issue #686).
    ///
    /// `None` history refuses: unavailable history is not absence of
    /// revocation and never restores as an empty closure. Stale (fence or
    /// revision drift, including drift against this snapshot's fence, and a
    /// recorded commit epoch that is not current for this recovery fence) and
    /// unknown (invalid, unordered, or non-revoked closure) evidence refuse
    /// likewise. A revoked origin and its dependent grants stay suppressed
    /// in the restored owner; unrelated valid grants restore exactly as the
    /// snapshot carries them, with the exact suppressed set reported.
    ///
    /// The legacy [`from_snapshot`](Self::from_snapshot) preserves its
    /// exact prior behavior for previously-admitted callers.
    ///
    /// `operation` is the admitted principal, task, work scope, observing
    /// receipt, and causal transaction position the origin-bound recheck runs
    /// under. The owner snapshot and the revocation-history evidence carry
    /// none of those five coordinates: the snapshot is a grant/effect payload
    /// (schema, version, fence, grant graph, effect authorizer, hydrations,
    /// legacy migration) and the evidence is a fence, a durable source
    /// revision, and per-closure owner namespace/digest/bounds records. The
    /// graph is a pure authority evaluator with no plan, no scope binding, and
    /// no Store readback, so it can derive no admitted task and no causal
    /// position, and neither can this restore. `AuthorityOwner` therefore
    /// refuses to fabricate them: the recovering owner — the durable boundary
    /// that observed this state — supplies the identity it admitted, already
    /// refused by `RevocationOperationIdentity::admit` if any coordinate is
    /// blank, control-bearing, or carries no `transaction_sequence`. A
    /// recheck under an invented identity is not a recheck.
    pub fn from_snapshot_with_revocation_history(
        snapshot: &AuthorityOwnerSnapshot,
        expected_fence: &StateFence,
        history: Option<&RevocationHistoryEvidence>,
        operation: &RevocationOperationIdentity,
    ) -> Result<AuthorityRestoreOutcome, CompositionError> {
        let snapshot = AuthorityOwnerSnapshot::canonical_durable_snapshot(snapshot)?;
        snapshot.validate_against(expected_fence)?;
        let evidence = history.ok_or_else(|| {
            CompositionError::Recovery(
                "authority revocation history is unavailable; unavailable history is not absence of revocation"
                    .to_owned(),
            )
        })?;
        // #1142: the fence the history was READ at is compared against this
        // live recovery fence. The old second clause compared that same fence
        // against `snapshot.state_fence`, which the `validate_against` above had
        // already proven equal by construction, so it could never refuse.
        if evidence.state_fence != *expected_fence {
            return Err(CompositionError::Recovery(
                "authority revocation history is stale for this recovery fence".to_owned(),
            ));
        }
        // The fence each closure was actually COMMITTED at, recorded in its own
        // durable commit receipt, is then compared against the same live fence.
        // That is the recorded-versus-live comparison on this path: the recorded
        // value is sourced from the commit and the live value from the Kernel's
        // current recovery fence, so it can refuse a closure committed under a
        // foreign lineage or under an epoch this restore has not reached. It
        // runs before any grant is restored.
        if evidence
            .require_recorded_commit_epochs_current(expected_fence)
            .is_err()
        {
            return Err(CompositionError::Recovery(
                "authority revocation history carries a recorded commit epoch that is not current \
                 for this recovery fence"
                    .to_owned(),
            ));
        }
        if evidence.source_revision != snapshot.grant_graph.revision {
            return Err(CompositionError::Recovery(
                "authority revocation history revision disagrees with the owner graph".to_owned(),
            ));
        }
        let outcome = GrantGraph::from_recovery_snapshot_with_revocation_history(
            &snapshot.grant_graph,
            Some(evidence),
            operation,
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
                effect_obligations: BTreeMap::new(),
                last_revocation_source_revision: Some(evidence.source_revision),
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
    ///
    /// The emitted snapshot is serializable history only: it never proves
    /// durable persistence of this generation's transitions. Dispatch and
    /// observation progress observed since restore are owner-retained (see
    /// `effect_obligations`) until the durable owner write path persists
    /// them; only validated receipts reconcile a transition.
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
            legacy_grant_graph_migration: None,
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
    /// Boxed because the transition request carries the whole bound
    /// operation; the box is a representation choice only and changes no
    /// field or proof.
    RootTransition(Box<RootTransitionActivationRequest>),
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
            Self::RootTransition(request) => request.snapshot_id(),
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
            Self::RootTransition(request) => request.binding(),
        }
    }

    /// Returns the retention-ledger key, namespacing grants from introductions
    /// from transitions so one identity can never alias another family.
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
            Self::RootTransition(request) => request.ledger_key(),
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
    Active {
        activation_id: String,
        transition_receipt: Option<Box<RootTransitionActivationReceipt>>,
    },
    RevocationIntended,
    Revoked {
        revocation_id: String,
    },
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

    /// Returns the complete validated owner-issued receipt for an active root
    /// transition. Other authority presentations do not carry this receipt.
    #[must_use]
    pub fn transition_receipt(&self) -> Option<&RootTransitionActivationReceipt> {
        match &self.state {
            AuthorityPresentationState::Active {
                transition_receipt: Some(receipt),
                ..
            } => Some(receipt),
            _ => None,
        }
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
                    transition_receipt: None,
                };
                Ok(())
            }
            _ => Err(CompositionError::Authority(P07PortError::InvalidBinding)),
        }
    }

    /// Records a validated transition activation receipt for the exact retained
    /// transition. Only a `Committed` receipt whose every committed field
    /// agrees with the retained request moves the presentation to `Active`; a
    /// receipt bound to another snapshot or epoch, a receipt that disagrees
    /// with the retained bytes, or a second activation on a recorded identity
    /// fails closed without touching the retained state.
    pub fn note_transition_activated(
        &mut self,
        receipt: &RootTransitionActivationReceipt,
    ) -> Result<(), CompositionError> {
        let PresentedAuthorityRequest::RootTransition(request) = &self.request else {
            return Err(CompositionError::Authority(P07PortError::InvalidBinding));
        };
        self.check_receipt_binding(
            receipt.kernel_activation.snapshot_id.as_str(),
            &receipt.kernel_activation.authority_epoch,
        )?;
        receipt
            .validate(request)
            .map_err(|error| CompositionError::Authority(map_transition_receipt_error(&error)))?;
        match self.state {
            AuthorityPresentationState::Pending | AuthorityPresentationState::UnknownOutcome => {
                self.state = AuthorityPresentationState::Active {
                    activation_id: receipt.kernel_activation.activation_id.clone(),
                    transition_receipt: Some(Box::new(receipt.clone())),
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

/// Maps a refused transition receipt onto the typed P-07 vocabulary.
///
/// A receipt that does not commit the exact presented operation is an identity
/// conflict, never a silent success: the caller re-serves fresh state instead
/// of retrying the same operation under a new request. This mirrors the daemon
/// adapter's `map_transition_validation_error` at the same boundary.
pub(crate) fn map_transition_receipt_error(error: &AuthorityError) -> P07PortError {
    match error {
        AuthorityError::IdentityConflict => P07PortError::IdentityConflict,
        AuthorityError::P07Unavailable => P07PortError::Unavailable,
        _ => P07PortError::InvalidBinding,
    }
}

/// Issue #1793, sequence 6-7: effect recovery obligations, reconcile-by-identity,
/// and separated recovery status.
///
/// I6.6 compiles an effectful action into proposal → authorization → receipt.
/// The [`EffectAuthorizer`] ledger durably retains the proposal and the exact
/// authorization decision; this section retains the recovery-side obligations
/// derived from those records — reserved scopes/resources, descendant and
/// compensation links, possible-external-effect flags, and dispatch/outcome
/// progress — so dependent work stays fenced by identity across restart.
///
/// I6.10 ordering applies: restore first restores historical authorizations,
/// then the caller applies CURRENT grant/revocation/contest state (via
/// [`AuthorityOwner::from_snapshot_with_revocation_history`]) and source
/// receipts, then rebuilds these obligations (via
/// [`AuthorityOwner::rebuild_effect_obligations`]) before dependent dispatch.
/// Missing or corrupt state stays blocked: unknown idempotency identities can
/// never dispatch or reconcile, and an unknown contest key is never read as
/// proof that an authorization exists.
///
/// Nothing here mints authority. Dispatch permission is still joined by
/// [`EffectAuthorizer::admit_effect_execution`] against the live lease, the
/// exact executor boundary, and the current contest state; these methods only
/// retain what the owner observed and report what is still pending.
fn require_effect_text(value: &str, field: &'static str) -> Result<(), CompositionError> {
    if value.trim().is_empty() {
        return Err(CompositionError::Recovery(format!(
            "effect recovery evidence has a blank {field}"
        )));
    }
    Ok(())
}

fn require_effect_digest(value: &str, field: &'static str) -> Result<(), CompositionError> {
    require_effect_text(value, field)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CompositionError::Recovery(format!(
            "effect recovery evidence has a malformed {field}"
        )));
    }
    Ok(())
}

/// Outcome evidence linked to one exact original effect by identity.
///
/// The evidence names the original operation identity and idempotency key and
/// carries the digest of the exact observed canonical receipt plus the
/// authorized owner/executor boundary that observed it. A compensation carries
/// its own evidence under its own identity; it never stands in for the
/// original's observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedOutcomeEvidence {
    /// Exact original operation identity the observation belongs to.
    pub operation_id: String,
    /// Exact original idempotency key the observation belongs to.
    pub idempotency_key: String,
    /// Digest of the exact observed canonical receipt.
    pub canonical_receipt_sha256: String,
    /// Authorized owner/executor boundary that observed the effect.
    pub observed_by: String,
}

impl LinkedOutcomeEvidence {
    /// Builds validated linked outcome evidence. Blank identities, a
    /// malformed receipt digest, or a blank observer refuse here, before any
    /// ledger is touched.
    pub fn new(
        operation_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        canonical_receipt_sha256: impl Into<String>,
        observed_by: impl Into<String>,
    ) -> Result<Self, CompositionError> {
        let evidence = Self {
            operation_id: operation_id.into(),
            idempotency_key: idempotency_key.into(),
            canonical_receipt_sha256: canonical_receipt_sha256.into(),
            observed_by: observed_by.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Validates every evidence coordinate.
    pub fn validate(&self) -> Result<(), CompositionError> {
        require_effect_text(&self.operation_id, "evidence.operation_id")?;
        require_effect_text(&self.idempotency_key, "evidence.idempotency_key")?;
        require_effect_digest(
            &self.canonical_receipt_sha256,
            "evidence.canonical_receipt_sha256",
        )?;
        require_effect_text(&self.observed_by, "evidence.observed_by")?;
        Ok(())
    }
}

/// Dispatch/outcome progress of one retained effect obligation.
///
/// Terminal reconciliation is immutable: once `Reconciled`, no further
/// transition is admitted. Unknown outcomes stay unknown until the exact
/// linked evidence reconciles them; a compensation link never advances this
/// state on its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectDispatchProgress {
    /// Historical authorization restored; no dispatch observed yet.
    AuthorizedNotDispatched,
    /// A sealed dispatch was admitted; the outcome is not yet observed.
    DispatchedAwaitingObservation,
    /// A post-dispatch lost result (or otherwise unobserved effect): the
    /// original unknown outcome is retained, not upgraded or rolled back.
    UnknownOutcome { reason: String },
    /// Terminal observed disposition with its linked outcome evidence.
    /// Immutable: reconciliation never rewrites this entry.
    Reconciled {
        outcome: EffectOutcome,
        evidence: LinkedOutcomeEvidence,
    },
}

impl EffectDispatchProgress {
    /// True only for an immutable terminal reconciliation.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Reconciled { .. })
    }
}

/// A separately authorized compensation linked to its original effect.
///
/// The compensation names its own operation identity and idempotency key,
/// both of which must carry their own stored authorization. The link is
/// audit lineage only: it never clears the original's uncertainty and never
/// proves that repeating the original action is safe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectCompensationLink {
    /// Idempotency key of the separately authorized compensation action.
    pub compensation_key: String,
    /// Operation identity of the separately authorized compensation action.
    pub compensation_operation_id: String,
}

/// One recovery-side effect obligation retained by identity.
///
/// Reserved scopes/resources, the bound operation/executor/lease identities,
/// and the possible-external-effect flag are derived from the stored
/// authorization record and never rewritten. Descendant and compensation
/// links, and dispatch/outcome progress, advance only through the explicit
/// owner methods below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedEffectObligation {
    /// Exact idempotency identity this obligation is keyed by.
    pub idempotency_key: String,
    /// Exact original operation identity.
    pub operation_id: String,
    /// Action identity from the compiled proposal.
    pub action_id: String,
    /// Reserved resource retained from the stored authorization.
    pub resource_ref: String,
    /// Reserved operation kind retained from the stored authorization.
    pub operation_kind: String,
    /// Exact authorized executor boundary.
    pub executor_boundary: String,
    /// Exact authorizing lease identity.
    pub lease_id: String,
    /// Verifier/receipt obligations bound at authorization time.
    pub receipt_obligations: Vec<ReceiptObligation>,
    /// True when the admitted effect class may have external effects, so
    /// dependents must assume the effect could have escaped local rollback.
    pub possible_external_effect: bool,
    /// Dispatch/outcome progress observed so far.
    pub progress: EffectDispatchProgress,
    /// Explicitly linked descendant operation identities fenced with this
    /// obligation until it reconciles.
    pub descendants: BTreeSet<String>,
    /// Separately authorized compensations linked for audit. They never
    /// advance `progress` on their own.
    pub compensations: Vec<EffectCompensationLink>,
}

impl RetainedEffectObligation {
    /// Derives the immutable obligation half from one stored authorization
    /// record. Progress starts at `AuthorizedNotDispatched` with no links;
    /// live transitions are reported through the owner methods.
    fn from_authorized_record(record: &AuthorizedEffectRecoveryRecord) -> Self {
        Self {
            idempotency_key: record.idempotency_key.clone(),
            operation_id: record.operation.operation_id.as_str().to_owned(),
            action_id: record.action_id.clone(),
            resource_ref: record.resource_ref.clone(),
            operation_kind: record.operation.operation_kind.clone(),
            executor_boundary: record.executor_boundary.clone(),
            lease_id: record.lease_id.clone(),
            receipt_obligations: record.receipt_obligations.clone(),
            possible_external_effect: record.operation.effect == EffectClass::ExternalEffect,
            progress: EffectDispatchProgress::AuthorizedNotDispatched,
            descendants: BTreeSet::new(),
            compensations: Vec::new(),
        }
    }
}

/// Proposal half of the separated recovery status: what was asked, with no
/// authority implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectProposalView {
    pub action_id: String,
    pub operation_id: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub operation_kind: String,
    pub resource_ref: String,
    pub canonical_payload_sha256: String,
}

/// Authorization half of the separated recovery status: the exact stored
/// decision bound to lease and executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectAuthorizationView {
    pub lease_id: String,
    pub executor_boundary: String,
    pub receipt_obligations: Vec<ReceiptObligation>,
}

/// Dispatch half of the separated recovery status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectDispatchView {
    /// No historical authorization exists for this identity.
    NeverAuthorized,
    /// Authorized; no dispatch observed.
    AwaitingDispatch,
    /// A dispatch was admitted, lost, or terminally reconciled: consult
    /// `outcome` for which.
    Dispatched,
}

/// Outcome half of the separated recovery status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectOutcomeView {
    /// Never authorized, or authorized with no observation yet.
    None,
    /// Dispatched; the outcome is not yet observed.
    AwaitingObservation,
    /// The original unknown outcome is retained; reconciliation is pending.
    Unknown { reason: String },
    /// Terminal observed disposition with its linked evidence coordinates.
    Reconciled {
        outcome: EffectOutcome,
        evidence_receipt_sha256: String,
        observed_by: String,
    },
}

/// One reason an effect still needs reconciliation. An empty list means
/// nothing is pending on the recovery path (it is not execution permission:
/// live dispatch still joins the lease, executor, and contest state).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectPendingItem {
    /// No historical authorization exists; missing state stays blocked.
    MissingAuthorization,
    /// The current standing is challenged by the named revoked roots and
    /// must be rebuilt from clean inputs before further reliance.
    ContestedByRoots { revoked_roots: Vec<String> },
    /// A sealed dispatch has no observation yet.
    DispatchUnobserved,
    /// The original unknown outcome is retained until linked evidence
    /// reconciles it.
    UnknownOutcomeUnreconciled,
}

/// Separated recovery status for one effect identity (issue #1793 seq 7).
///
/// Proposal, authorization, dispatch, outcome, and pending reconciliation
/// are exposed as independent sections with privacy-safe owned strings, so
/// a status reader can never mistake one section for another. `current_contest`
/// is the live contest overlay: per the effect ledger contract it reports
/// `Admissible` for unknown keys, so callers must join it with
/// `proposal.is_some()` — an admissible default for an unknown key is not
/// proof that an authorization exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectRecoveryStatus {
    pub idempotency_key: String,
    pub proposal: Option<EffectProposalView>,
    pub authorization: Option<EffectAuthorizationView>,
    pub dispatch: EffectDispatchView,
    pub outcome: EffectOutcomeView,
    pub pending: Vec<EffectPendingItem>,
    pub current_contest: DependentEffectState,
}

/// Current applicability rebuilt before reuse (issue #1793 seq 7).
///
/// Names the exact grant-graph revision, the durable revocation-history
/// source revision applied (`None` when restored without CURRENT history
/// evidence — that restore stays visibly incomplete), whether the closure
/// hydration feed is present, and which effects the current contest state
/// challenges. Missing or corrupt state is reported here, never defaulted
/// to an empty permissive registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectAuthorityApplicability {
    pub grant_graph_revision: u64,
    pub revocation_source_revision: Option<u64>,
    pub owner_hydrations_present: bool,
    pub contested_effect_keys: Vec<String>,
}

impl AuthorityOwner {
    /// Rebuilds recovery-side effect obligations after restart, before
    /// dependent dispatch (issue #1793 seq 6).
    ///
    /// Every stored historical authorization gains an obligation carrying
    /// its exact reserved scopes/resources, operation/executor/lease
    /// identities, receipt obligations, and possible-external-effect flag.
    /// Obligations already present keep their in-generation progress,
    /// descendant/compensation links, and terminal history: the rebuild
    /// never overwrites observed dispatch/outcome state, and obligations
    /// for identities absent from the ledger are retained (expiry or loss
    /// of a local queue entry does not release them).
    ///
    /// Returns the number of obligations newly derived from the ledger.
    pub fn rebuild_effect_obligations(&mut self) -> Result<usize, CompositionError> {
        let snapshot = self
            .effects
            .snapshot()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let mut created = 0;
        for record in &snapshot.records {
            if !self
                .effect_obligations
                .contains_key(&record.idempotency_key)
            {
                self.effect_obligations.insert(
                    record.idempotency_key.clone(),
                    RetainedEffectObligation::from_authorized_record(record),
                );
                created += 1;
            }
        }
        Ok(created)
    }

    /// Reports that the sealed dispatch for one retained effect was admitted
    /// at the effect boundary.
    ///
    /// Refuses unknown identities (missing state stays blocked, it is never
    /// treated as an empty permissive grant), currently contested
    /// authorizations, and any obligation that already left
    /// `AuthorizedNotDispatched` — including immutable terminal history.
    /// CURRENT revocation evidence must have been rebuilt first: an owner
    /// restored without history-bound evidence keeps every dispatch refused
    /// until a history-bound restore completes, so empty contest overlays
    /// are never read as absence of revocation. This records the owner's
    /// observation; execution permission itself was joined by
    /// `admit_effect_execution` against the live lease, executor, and
    /// contest state.
    pub fn note_effect_dispatch_admitted(
        &mut self,
        idempotency_key: &str,
    ) -> Result<(), CompositionError> {
        let obligation = self
            .effect_obligations
            .get_mut(idempotency_key)
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "effect dispatch names an identity with no retained authorization".to_owned(),
                )
            })?;
        if self.last_revocation_source_revision.is_none() {
            return Err(CompositionError::Recovery(
                "effect dispatch requires CURRENT revocation evidence; rebuild it with a history-bound restore before dependent use"
                    .to_owned(),
            ));
        }
        if self
            .effects
            .dependent_effect_state(idempotency_key)
            .is_contested()
        {
            return Err(CompositionError::Recovery(
                "effect dispatch is contested by current revocation state".to_owned(),
            ));
        }
        match &obligation.progress {
            EffectDispatchProgress::AuthorizedNotDispatched => {}
            EffectDispatchProgress::DispatchedAwaitingObservation
            | EffectDispatchProgress::UnknownOutcome { .. } => {
                return Err(CompositionError::Recovery(
                    "effect dispatch is already admitted for this identity".to_owned(),
                ));
            }
            EffectDispatchProgress::Reconciled { .. } => {
                return Err(CompositionError::Recovery(
                    "effect dispatch cannot re-open immutable terminal history".to_owned(),
                ));
            }
        }
        obligation.progress = EffectDispatchProgress::DispatchedAwaitingObservation;
        Ok(())
    }

    /// Retains a post-dispatch lost result (or otherwise unobserved effect)
    /// as the original unknown outcome.
    ///
    /// The obligation keeps its exact reserved scopes/resources and stays
    /// fenced until reconcile-by-identity. Terminal history can never be
    /// overwritten into unknown; unknown identities stay refused.
    pub fn note_effect_unknown_outcome(
        &mut self,
        idempotency_key: &str,
        reason: impl Into<String>,
    ) -> Result<(), CompositionError> {
        let reason = reason.into();
        require_effect_text(&reason, "unknown_outcome.reason")?;
        let obligation = self
            .effect_obligations
            .get_mut(idempotency_key)
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "effect outcome names an identity with no retained authorization".to_owned(),
                )
            })?;
        if obligation.progress.is_terminal() {
            return Err(CompositionError::Recovery(
                "effect outcome cannot overwrite immutable terminal history".to_owned(),
            ));
        }
        obligation.progress = EffectDispatchProgress::UnknownOutcome { reason };
        Ok(())
    }

    /// Reconciles the original effect through its authorized owner
    /// observation plus linked outcome evidence (issue #1793 seq 6).
    ///
    /// The evidence must name this exact idempotency identity and the exact
    /// stored operation identity, and the outcome must be terminal: an
    /// unknown outcome is retained via [`Self::note_effect_unknown_outcome`],
    /// never reconciled, and a compensation link never substitutes for the
    /// original's observation. An already-reconciled obligation refuses: the
    /// linked outcome evidence is appended once and terminal history is
    /// never overwritten. Reconciliation releases the same-scope fence.
    pub fn reconcile_effect_outcome(
        &mut self,
        idempotency_key: &str,
        outcome: EffectOutcome,
        evidence: LinkedOutcomeEvidence,
    ) -> Result<(), CompositionError> {
        evidence.validate()?;
        if matches!(outcome, EffectOutcome::UnknownOutcome { .. }) {
            return Err(CompositionError::Recovery(
                "effect reconciliation requires a terminal observed outcome".to_owned(),
            ));
        }
        let obligation = self
            .effect_obligations
            .get_mut(idempotency_key)
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "effect reconciliation names an identity with no retained authorization"
                        .to_owned(),
                )
            })?;
        if evidence.idempotency_key != obligation.idempotency_key
            || evidence.operation_id != obligation.operation_id
        {
            return Err(CompositionError::Recovery(
                "effect outcome evidence does not match the retained operation identity".to_owned(),
            ));
        }
        if obligation.progress.is_terminal() {
            return Err(CompositionError::Recovery(
                "effect reconciliation cannot overwrite immutable terminal history".to_owned(),
            ));
        }
        obligation.progress = EffectDispatchProgress::Reconciled { outcome, evidence };
        Ok(())
    }

    /// Links a separately authorized compensation to its original effect.
    ///
    /// Both identities must carry their own retained authorization: the
    /// compensation is a separately authorized, separately observed action,
    /// never an implicit reopening of the original. The link is audit
    /// lineage only — it never advances the original's progress and never
    /// erases original uncertainty. Only [`Self::reconcile_effect_outcome`]
    /// with the proper observed disposition releases the original fence.
    pub fn link_effect_compensation(
        &mut self,
        original_key: &str,
        compensation_key: &str,
        compensation_operation_id: &str,
    ) -> Result<(), CompositionError> {
        require_effect_text(compensation_key, "compensation.idempotency_key")?;
        require_effect_text(compensation_operation_id, "compensation.operation_id")?;
        let compensation = self
            .effect_obligations
            .get(compensation_key)
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "effect compensation names an identity with no retained authorization"
                        .to_owned(),
                )
            })?;
        if compensation.operation_id != compensation_operation_id {
            return Err(CompositionError::Recovery(
                "effect compensation operation identity disagrees with the retained record"
                    .to_owned(),
            ));
        }
        let original = self
            .effect_obligations
            .get_mut(original_key)
            .ok_or_else(|| {
                CompositionError::Recovery(
                    "effect compensation names an original with no retained authorization"
                        .to_owned(),
                )
            })?;
        if original
            .compensations
            .iter()
            .any(|link| link.compensation_key == compensation_key)
        {
            return Err(CompositionError::Recovery(
                "effect compensation is already linked to this original".to_owned(),
            ));
        }
        original.compensations.push(EffectCompensationLink {
            compensation_key: compensation_key.to_owned(),
            compensation_operation_id: compensation_operation_id.to_owned(),
        });
        Ok(())
    }

    /// Links an explicitly related descendant operation under one retained
    /// obligation.
    ///
    /// Both identities must carry their own retained authorization. The
    /// descendant stays fenced with the parent obligation's scope until the
    /// parent reconciles; retrying the parent under a new operation identity
    /// still requires the documented rollback/relationship and fresh
    /// admission.
    pub fn link_effect_descendant(
        &mut self,
        parent_key: &str,
        child_key: &str,
    ) -> Result<(), CompositionError> {
        require_effect_text(child_key, "descendant.idempotency_key")?;
        if parent_key == child_key {
            return Err(CompositionError::Recovery(
                "effect descendant cannot link an identity to itself".to_owned(),
            ));
        }
        if !self.effect_obligations.contains_key(child_key) {
            return Err(CompositionError::Recovery(
                "effect descendant names an identity with no retained authorization".to_owned(),
            ));
        }
        let parent = self.effect_obligations.get_mut(parent_key).ok_or_else(|| {
            CompositionError::Recovery(
                "effect descendant names a parent with no retained authorization".to_owned(),
            )
        })?;
        if !parent.descendants.insert(child_key.to_owned()) {
            return Err(CompositionError::Recovery(
                "effect descendant is already linked to this parent".to_owned(),
            ));
        }
        Ok(())
    }

    /// Per-identity dispatch fence, consulted before dependent dispatch.
    ///
    /// Returns true (blocked) when no retained authorization exists for the
    /// identity, when CURRENT revocation evidence was never rebuilt for this
    /// owner (an owner restored without history-bound evidence stays fenced
    /// until a history-bound restore completes, even with empty contest
    /// overlays), when the current contest state challenges it, or when its
    /// obligation already left `AuthorizedNotDispatched` — dispatched but
    /// unobserved, unknown, or terminally reconciled identities never
    /// re-dispatch under the same identity. Only a known, uncontested,
    /// never-dispatched authorization on a history-bound owner reports
    /// false. A retried operation needs its own explicitly linked
    /// new-operation identity and fresh admission.
    #[must_use]
    pub fn effect_dispatch_blocked(&self, idempotency_key: &str) -> bool {
        if self.last_revocation_source_revision.is_none() {
            return true;
        }
        let Some(obligation) = self.effect_obligations.get(idempotency_key) else {
            return true;
        };
        if self
            .effects
            .dependent_effect_state(idempotency_key)
            .is_contested()
        {
            return true;
        }
        !matches!(
            obligation.progress,
            EffectDispatchProgress::AuthorizedNotDispatched
        )
    }

    /// Same-scope dependent-work fence (issue #1793 seq 6).
    ///
    /// Returns true while any non-terminal obligation reserves exactly
    /// `resource_ref`: dispatched-but-unobserved, unknown-outcome, and
    /// contested-but-authorized obligations all keep the dependent ordering
    /// scope blocked. Terminal reconciliation releases the scope, and scopes
    /// with no retained obligation stay eligible, so independent work
    /// proceeds while dependent work waits.
    #[must_use]
    pub fn dependent_scope_blocked(&self, resource_ref: &str) -> bool {
        self.effect_obligations.values().any(|obligation| {
            !obligation.progress.is_terminal() && obligation.resource_ref == resource_ref
        })
    }

    /// Separated recovery status for one effect identity (issue #1793 seq 7).
    ///
    /// Proposal, authorization, dispatch, outcome, and pending
    /// reconciliation are reported as independent sections. Unknown
    /// identities report no proposal/authorization, `NeverAuthorized`
    /// dispatch, `None` outcome, and a `MissingAuthorization` pending item —
    /// never an admissible default.
    #[must_use]
    pub fn effect_recovery_status(&self, idempotency_key: &str) -> EffectRecoveryStatus {
        let obligation = self.effect_obligations.get(idempotency_key);
        let current_contest = self.effects.dependent_effect_state(idempotency_key);
        let contested = current_contest.is_contested();
        let (proposal, authorization, dispatch, outcome) = match obligation {
            None => (
                None,
                None,
                EffectDispatchView::NeverAuthorized,
                EffectOutcomeView::None,
            ),
            Some(obligation) => {
                let ledger = self.effect_ledger_record(idempotency_key);
                let proposal = EffectProposalView {
                    action_id: obligation.action_id.clone(),
                    operation_id: obligation.operation_id.clone(),
                    request_id: ledger
                        .as_ref()
                        .map(|record| record.operation.request_id.as_str().to_owned())
                        .unwrap_or_default(),
                    idempotency_key: obligation.idempotency_key.clone(),
                    operation_kind: obligation.operation_kind.clone(),
                    resource_ref: obligation.resource_ref.clone(),
                    canonical_payload_sha256: ledger
                        .map(|record| record.canonical_payload_sha256.clone())
                        .unwrap_or_default(),
                };
                let authorization = EffectAuthorizationView {
                    lease_id: obligation.lease_id.clone(),
                    executor_boundary: obligation.executor_boundary.clone(),
                    receipt_obligations: obligation.receipt_obligations.clone(),
                };
                let (dispatch, outcome) = match &obligation.progress {
                    EffectDispatchProgress::AuthorizedNotDispatched => (
                        EffectDispatchView::AwaitingDispatch,
                        EffectOutcomeView::None,
                    ),
                    EffectDispatchProgress::DispatchedAwaitingObservation => (
                        EffectDispatchView::Dispatched,
                        EffectOutcomeView::AwaitingObservation,
                    ),
                    EffectDispatchProgress::UnknownOutcome { reason } => (
                        EffectDispatchView::Dispatched,
                        EffectOutcomeView::Unknown {
                            reason: reason.clone(),
                        },
                    ),
                    EffectDispatchProgress::Reconciled { outcome, evidence } => (
                        EffectDispatchView::Dispatched,
                        EffectOutcomeView::Reconciled {
                            outcome: outcome.clone(),
                            evidence_receipt_sha256: evidence.canonical_receipt_sha256.clone(),
                            observed_by: evidence.observed_by.clone(),
                        },
                    ),
                };
                (Some(proposal), Some(authorization), dispatch, outcome)
            }
        };
        let mut pending = Vec::new();
        if obligation.is_none() {
            pending.push(EffectPendingItem::MissingAuthorization);
        }
        if contested {
            pending.push(EffectPendingItem::ContestedByRoots {
                revoked_roots: current_contest
                    .revoked_roots()
                    .map(|roots| roots.iter().cloned().collect())
                    .unwrap_or_default(),
            });
        }
        match &outcome {
            EffectOutcomeView::AwaitingObservation => {
                pending.push(EffectPendingItem::DispatchUnobserved);
            }
            EffectOutcomeView::Unknown { .. } => {
                pending.push(EffectPendingItem::UnknownOutcomeUnreconciled);
            }
            EffectOutcomeView::None | EffectOutcomeView::Reconciled { .. } => {}
        }
        EffectRecoveryStatus {
            idempotency_key: idempotency_key.to_owned(),
            proposal,
            authorization,
            dispatch,
            outcome,
            pending,
            current_contest,
        }
    }

    /// Idempotency keys with at least one pending reconciliation item, in
    /// obligation order. Drives the status-path sweep without implying
    /// execution permission for any key.
    #[must_use]
    pub fn pending_effect_keys(&self) -> Vec<String> {
        self.effect_obligations
            .keys()
            .filter(|key| !self.effect_recovery_status(key).pending.is_empty())
            .cloned()
            .collect()
    }

    /// Current applicability rebuilt before reuse (issue #1793 seq 7).
    ///
    /// Reports the exact grant-graph revision, the durable
    /// revocation-history source revision applied at restore, whether the
    /// closure hydration feed is present, and the currently contested
    /// effects. A `None` source revision means the owner restored without
    /// CURRENT history evidence: applicability is visibly incomplete and
    /// dependent reuse must stay fenced until a history-bound restore
    /// completes.
    #[must_use]
    pub fn authority_applicability(&self) -> EffectAuthorityApplicability {
        EffectAuthorityApplicability {
            grant_graph_revision: self.grants.revision(),
            revocation_source_revision: self.last_revocation_source_revision,
            owner_hydrations_present: self.owner_hydrations.is_some(),
            contested_effect_keys: self.effects.contested_effect_keys(),
        }
    }

    /// Reads one stored authorization record by identity. The ledger is the
    /// authority for what was authorized; the obligation map is the
    /// authority for what has been observed since.
    fn effect_ledger_record(
        &self,
        idempotency_key: &str,
    ) -> Option<AuthorizedEffectRecoveryRecord> {
        self.effects.snapshot().ok().and_then(|snapshot| {
            snapshot
                .records
                .into_iter()
                .find(|record| record.idempotency_key == idempotency_key)
        })
    }
}
