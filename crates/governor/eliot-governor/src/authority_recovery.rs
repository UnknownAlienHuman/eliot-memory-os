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
    EffectAuthorizer, EffectAuthorizerRecoverySnapshot, GRANT_GRAPH_RECOVERY_SCHEMA,
    GrantActivationRequest, GrantGraph, GrantGraphRecoverySnapshot, GrantRevocationRequest,
    GrantStatus, IntroductionActivationRequest, IntroductionRevocationRequest, IntroductionStatus,
    LEGACY_GRANT_GRAPH_RECOVERY_VERSION, P07PortError, RevocationHistoryEvidence, SnapshotId,
    SuppressedGrant,
};
use eliot_contracts::{EpochId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_receipts::AuthorityBinding;
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
            &snapshot.grant_graph,
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
