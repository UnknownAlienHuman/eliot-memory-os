use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::StateFence;
use eliot_influence::{
    BoundedRevocationRequest, ClosureCompleteness, InfluenceEdgeDisposition, OmissionCause,
    QualifiedInfluenceEdge, RevocationOmission,
};
use eliot_receipts::{AuthorityBinding, EffectClass, SessionBinding, WorkScopeBinding};
use eliot_security_contracts::{EffectCeiling, RevocationReason};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::revocation_history::derive_suppressions;
use crate::{AuthorityError, GrantRestoreOutcome, RevocationHistoryError, validate_text};

const REVOCATION_PAGE_EDGE_LIMIT: u64 = 256;
const REVOCATION_PAGE_WORK_LIMIT: u64 = 513;

fn map_bounded_revocation_error(error: eliot_influence::InfluenceError) -> AuthorityError {
    AuthorityError::BoundedRevocation(error)
}

fn map_bounded_history_error(error: AuthorityError) -> RevocationHistoryError {
    match error {
        AuthorityError::BoundedRevocation(error) => {
            RevocationHistoryError::BoundedRevocation(error)
        }
        _ => RevocationHistoryError::UnknownHistory,
    }
}

macro_rules! text_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, AuthorityError> {
                let value = value.into();
                validate_text(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

text_id!(GrantId, "grant_id");
text_id!(SnapshotId, "snapshot_id");
text_id!(IntroductionId, "introduction_id");
text_id!(PrincipalRef, "principal_ref");

/// Caller-supplied logical time. The crate never reads a wall clock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogicalTime(u64);

impl LogicalTime {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Explicit evidence required after an admitted effect.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptObligation {
    CanonicalEffectReceipt,
    ExternalReadback,
    IndependentVerification,
    Named(String),
}

impl ReceiptObligation {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        if let Self::Named(value) = self {
            validate_text(value, "receipt_obligation")?;
        }
        Ok(())
    }
}

/// Exact operation/resource/effect authority carried by one lineage path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySet {
    operations: BTreeSet<String>,
    resources: BTreeSet<String>,
    max_effect: EffectClass,
}

impl AuthoritySet {
    pub fn new(
        operations: impl IntoIterator<Item = String>,
        resources: impl IntoIterator<Item = String>,
        max_effect: EffectClass,
    ) -> Result<Self, AuthorityError> {
        let operations = operations.into_iter().collect::<BTreeSet<_>>();
        let resources = resources.into_iter().collect::<BTreeSet<_>>();
        if operations.is_empty() {
            return Err(AuthorityError::InvalidField("allowed_operations"));
        }
        if resources.is_empty() {
            return Err(AuthorityError::InvalidField("allowed_resources"));
        }
        for operation in &operations {
            validate_text(operation, "allowed_operations")?;
        }
        for resource in &resources {
            validate_text(resource, "allowed_resources")?;
        }
        Ok(Self {
            operations,
            resources,
            max_effect,
        })
    }

    pub fn operations(&self) -> &BTreeSet<String> {
        &self.operations
    }

    pub fn resources(&self) -> &BTreeSet<String> {
        &self.resources
    }

    pub const fn max_effect(&self) -> EffectClass {
        self.max_effect
    }

    pub fn allows(&self, operation: &str, resource: &str, effect: EffectClass) -> bool {
        self.operations.contains(operation)
            && self.resources.contains(resource)
            && effect_rank(effect) <= effect_rank(self.max_effect)
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.operations.is_subset(&parent.operations)
            && self.resources.is_subset(&parent.resources)
            && effect_rank(self.max_effect) <= effect_rank(parent.max_effect)
    }

    pub fn is_strict_subset_of(&self, parent: &Self) -> bool {
        self.is_subset_of(parent) && self != parent
    }

    pub fn intersection(&self, other: &Self) -> Result<Self, AuthorityError> {
        Self::new(
            self.operations.intersection(&other.operations).cloned(),
            self.resources.intersection(&other.resources).cloned(),
            if effect_rank(self.max_effect) <= effect_rank(other.max_effect) {
                self.max_effect
            } else {
                other.max_effect
            },
        )
    }
}

pub(crate) const fn effect_rank(effect: EffectClass) -> u8 {
    match effect {
        EffectClass::Read => 0,
        EffectClass::Candidate => 1,
        EffectClass::ReversibleMutation => 2,
        EffectClass::ExternalEffect => 3,
    }
}

fn source_effect_rank(ceiling: EffectCeiling) -> u8 {
    match ceiling {
        EffectCeiling::ReadOnly => 0,
        EffectCeiling::CandidateOnly => 1,
        EffectCeiling::NoExternalEffect => 2,
    }
}

/// #2875 item 10: the single source-level meaning of "cross-root".
///
/// Every authority-root comparison in this module — graph validation,
/// effective-path construction, closure enumeration, revocation edge
/// declaration, and recovery partition — calls this function, so comments,
/// traversal, and authority use cannot maintain different meanings of a
/// root crossing. Ordinary delegation stays inside one root. This module has
/// no trusted root-transition issuer or verifier, so a caller cannot
/// authorize re-rooting by setting a string while borrowing the parent's
/// holder and authority.
fn crosses_authority_root(from_root: &str, to_root: &str) -> bool {
    from_root != to_root
}

/// Item-10 edge invariant: one delegation edge is authorized authority
/// inheritance when it stays inside one root or has a transition in the
/// graph's admitted-transition map for this exact parent/child pair. The
/// public construction and recovery boundaries reject caller-supplied
/// receipts because this module has no trusted issuer verifier. Shared by
/// [`GrantGraph::validate_edges`], effective-path construction, revocation
/// edge declaration, the closure verdict walk, and the recovery partition.
fn edge_is_authorized(
    parent: &CapabilityGrant,
    child: &CapabilityGrant,
    transitions: &BTreeMap<(GrantId, GrantId), RootTransitionReceipt>,
) -> bool {
    !crosses_authority_root(&parent.authority_root_ref, &child.authority_root_ref)
        || transitions.contains_key(&(parent.grant_id.clone(), child.grant_id.clone()))
}

/// The four narrowing clauses: issuer is the parent's holder, authority is
/// a strict subset, `expires_at` is not later, `max_uses` is not larger.
/// Shared by edge validation, legacy-cross-root migration, and quarantined
/// record restore, so a crossing — authorized or quarantined — can never
/// widen authority, effect, or lifetime.
fn check_narrowing(
    parent: &CapabilityGrant,
    child: &CapabilityGrant,
) -> Result<(), AuthorityError> {
    if child.issuer != parent.holder
        || !child.authority.is_strict_subset_of(&parent.authority)
        || child.expires_at > parent.expires_at
        || child.max_uses > parent.max_uses
    {
        return Err(AuthorityError::GrantNotNarrower(child.grant_id.clone()));
    }
    Ok(())
}

/// Deterministic legacy label for one quarantined cross-root edge. It joins
/// grant IDs with delimiters, so distinct edges can collide when IDs contain
/// `:`; recovery refuses such collisions instead of replacing retained data.
fn quarantine_relation_id(parent: &GrantId, child: &GrantId) -> String {
    format!(
        "cross_root_quarantine:{}:{}",
        parent.as_str(),
        child.as_str()
    )
}

/// Immutable lifecycle state; narrowing is a new grant revision, not a state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    PendingActivation,
    Active,
    Revoked,
    Expired,
    Stale,
}

/// One immutable canonical delegation edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityGrant {
    pub grant_id: GrantId,
    pub parent_grant_id: Option<GrantId>,
    pub authority_root_ref: String,
    pub issuer: PrincipalRef,
    pub holder: PrincipalRef,
    pub authority: AuthoritySet,
    pub inherited_source_ceiling: Option<EffectCeiling>,
    pub binding: AuthorityBinding,
    pub issued_at: LogicalTime,
    pub expires_at: LogicalTime,
    pub max_uses: u32,
    pub status: GrantStatus,
}

impl CapabilityGrant {
    pub fn validate_local(&self) -> Result<(), AuthorityError> {
        validate_text(&self.authority_root_ref, "authority_root_ref")?;
        self.binding
            .state_fence
            .validate()
            .map_err(|_| AuthorityError::FenceMismatch)?;
        if !self
            .binding
            .authority_epoch
            .is_same_authority(&self.binding.state_fence.authority_epoch)
        {
            return Err(AuthorityError::EpochMismatch);
        }
        if effect_rank(self.authority.max_effect()) > effect_rank(self.binding.allowed_effect) {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        if let Some(source_ceiling) = self.inherited_source_ceiling
            && effect_rank(self.authority.max_effect()) > source_effect_rank(source_ceiling)
        {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        if self.expires_at <= self.issued_at {
            return Err(AuthorityError::InvalidField("issued_at_expires_at"));
        }
        if self.max_uses == 0 {
            return Err(AuthorityError::InvalidField("max_uses"));
        }
        Ok(())
    }
}

/// Caller-supplied root-transition receipt shape retained for wire
/// compatibility (#2875 item 4).
///
/// This module has no production owner-issued transition source or verifier.
/// It therefore rejects every nonempty receipt input at graph construction
/// and recovery; matching caller-supplied fields cannot authorize a crossing.
/// A future implementation must bind this shape to a trusted issuance path
/// before it can become authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootTransitionReceipt {
    /// Claimed transition identity; it does not prove owner issuance.
    pub transition_id: String,
    /// Claimed delegating parent grant; the crossing source.
    pub parent_grant_id: String,
    /// Claimed re-rooted child grant; the crossing dependent.
    pub child_grant_id: String,
    /// Exact parent root the edge leaves.
    pub from_authority_root_ref: String,
    /// Exact child root the edge enters.
    pub to_authority_root_ref: String,
    /// Claimed owner principal; matching the parent's holder does not prove
    /// that the owner authorized the re-root.
    pub issuer: String,
    /// Caller-supplied fence/epoch binding for the claimed crossing.
    pub binding: AuthorityBinding,
    /// Claimed graph revision. It is not verified as an issuance record.
    pub admitted_at_revision: u64,
}

pub const GRANT_GRAPH_RECOVERY_SCHEMA: &str = "eliot.authority.grant-graph-recovery";
pub const GRANT_GRAPH_RECOVERY_VERSION: u16 = 1;

/// Complete durable state of a grant graph, in deterministic wire form.
///
/// `grants` carries authority lineage only after validation. Pre-fix snapshots
/// with no transition receipts migrate cross-root active edges to quarantined
/// relations. Any nonempty `root_transitions` history is rejected because
/// owner issuance cannot be verified here; the input bytes are not rewritten
/// or silently discarded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantGraphRecoverySnapshot {
    pub schema: String,
    pub version: u16,
    pub revision: u64,
    pub grants: Vec<GrantRecoveryRecord>,
    pub revoked: Vec<String>,
    /// Legacy claimed transition receipts. Nonempty input is rejected because
    /// owner issuance cannot be verified by this module.
    #[serde(default)]
    pub root_transitions: Vec<RootTransitionReceipt>,
    /// Inert quarantined cross-root relations in relation-id order (#2875).
    #[serde(default)]
    pub quarantined_cross_root: Vec<QuarantinedCrossRootRecord>,
}

/// One complete grant record retained by a recovery snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantRecoveryRecord {
    pub grant_id: String,
    pub parent_grant_id: Option<String>,
    pub authority_root_ref: String,
    pub issuer: String,
    pub holder: String,
    pub allowed_operations: Vec<String>,
    pub allowed_resources: Vec<String>,
    pub max_effect: EffectClass,
    pub inherited_source_ceiling: Option<EffectCeiling>,
    pub binding: AuthorityBinding,
    pub issued_at: u64,
    pub expires_at: u64,
    pub max_uses: u32,
    pub status: GrantStatus,
}

impl GrantGraphRecoverySnapshot {
    /// Validates both the deterministic wire shape and the graph semantics
    /// that would be enforced when this snapshot is restored.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.validate_wire()?;
        GrantGraphRecoverySnapshot::restore_owned(self).map(|_| ())
    }

    fn validate_wire(&self) -> Result<(), AuthorityError> {
        if self.schema != GRANT_GRAPH_RECOVERY_SCHEMA {
            return Err(AuthorityError::InvalidField("grant_graph_recovery.schema"));
        }
        if self.version != GRANT_GRAPH_RECOVERY_VERSION {
            return Err(AuthorityError::InvalidField("grant_graph_recovery.version"));
        }
        if !self.root_transitions.is_empty() {
            return Err(AuthorityError::InvalidField(
                "root_transition_receipt.owner_issuance_unverified",
            ));
        }
        if self.revision == 0 {
            return Err(AuthorityError::InvalidField("grant_graph_revision"));
        }
        let mut previous = None;
        for record in &self.grants {
            validate_text(&record.grant_id, "grant_id")?;
            if let Some(previous) = previous
                && previous >= record.grant_id.as_str()
            {
                return Err(AuthorityError::InvalidField("grant_graph_recovery.grants"));
            }
            previous = Some(record.grant_id.as_str());
        }
        let mut previous = None;
        for revoked in &self.revoked {
            validate_text(revoked, "revoked_grant_id")?;
            if let Some(previous) = previous
                && previous >= revoked.as_str()
            {
                return Err(AuthorityError::InvalidField("grant_graph_recovery.revoked"));
            }
            previous = Some(revoked.as_str());
        }
        let mut previous = None;
        for record in &self.quarantined_cross_root {
            validate_text(&record.relation_id, "quarantined_cross_root.relation_id")?;
            if let Some(previous) = previous
                && previous >= record.relation_id.as_str()
            {
                return Err(AuthorityError::InvalidField(
                    "grant_graph_recovery.quarantined_cross_root",
                ));
            }
            previous = Some(record.relation_id.as_str());
        }
        Ok(())
    }

    /// Restores owned graph state: same-root authority and inert quarantined
    /// relations (#2875 item 9). Transition receipt history is rejected before
    /// this graph construction because this module cannot verify owner
    /// issuance.
    ///
    /// Grants whose parent edge stays inside one root restore into the
    /// authority map. Grants whose parent edge crosses roots migrate to inert
    /// [`QuarantinedCrossRootRelation`] records with their full
    /// lineage retained, as do their transitive descendants; migration is
    /// deterministic, so exact replay restores the exact same graph. A
    /// cross-root edge that is not even a narrowing is not lineage and is
    /// refused with [`AuthorityError::GrantNotNarrower`]. Explicit
    /// quarantined records restore as inert evidence: cross-root edges are
    /// accepted only as quarantine, while same-root descendants require an
    /// already-quarantined parent. A same-root child under an admitted parent,
    /// a mismatched parent root, or an admitted-child collision fails closed.
    /// A legacy cross-root child therefore can never restore as active
    /// authority.
    fn restore_owned(snapshot: &GrantGraphRecoverySnapshot) -> Result<GrantGraph, AuthorityError> {
        if !snapshot.root_transitions.is_empty() {
            return Err(AuthorityError::InvalidField(
                "root_transition_receipt.owner_issuance_unverified",
            ));
        }
        let mut full_map = BTreeMap::new();
        for record in &snapshot.grants {
            let grant = grant_from_recovery_record(record)?;
            grant.validate_local()?;
            let grant_id = grant.grant_id.clone();
            if full_map.insert(grant_id.clone(), grant).is_some() {
                return Err(AuthorityError::DuplicateGrant(grant_id));
            }
        }
        for grant in full_map.values() {
            if let Some(parent_id) = &grant.parent_grant_id
                && !full_map.contains_key(parent_id)
            {
                return Err(AuthorityError::MissingParent(parent_id.clone()));
            }
        }
        let probe = GrantGraph {
            grants: full_map,
            revoked: BTreeSet::new(),
            revision: snapshot.revision,
            transitions: BTreeMap::new(),
            quarantined: BTreeMap::new(),
        };
        probe.validate_cycles()?;
        let mut graph = probe.partition_restored()?;
        let mut pending: BTreeMap<GrantId, (GrantId, &QuarantinedCrossRootRecord)> =
            BTreeMap::new();
        for record in &snapshot.quarantined_cross_root {
            let child = grant_from_recovery_record(&record.child)?;
            child.validate_local()?;
            let parent_id = GrantId::new(record.parent_grant_id.clone())?;
            if child.parent_grant_id.as_ref() != Some(&parent_id) {
                return Err(AuthorityError::InvalidField("quarantined_cross_root.edge"));
            }
            if pending
                .insert(child.grant_id.clone(), (parent_id, record))
                .is_some()
            {
                return Err(AuthorityError::IdentityConflict);
            }
        }
        while !pending.is_empty() {
            let ready: Vec<GrantId> = pending
                .iter()
                .filter_map(|(child_id, (parent_id, _))| {
                    let parent_is_admitted = graph.grants.contains_key(parent_id);
                    let parent_is_quarantined = graph
                        .quarantined
                        .values()
                        .any(|relation| &relation.child.grant_id == parent_id);
                    (parent_is_admitted || parent_is_quarantined).then(|| child_id.clone())
                })
                .collect();
            if ready.is_empty() {
                let Some((_, (parent_id, _))) = pending.iter().next() else {
                    return Err(AuthorityError::InvalidField(
                        "quarantined_cross_root.lineage",
                    ));
                };
                if !pending.contains_key(parent_id) {
                    return Err(AuthorityError::MissingParent(parent_id.clone()));
                }
                return Err(AuthorityError::InvalidField(
                    "quarantined_cross_root.lineage",
                ));
            }
            for child_id in ready {
                let Some((_, record)) = pending.remove(&child_id) else {
                    return Err(AuthorityError::InvalidField(
                        "quarantined_cross_root.lineage",
                    ));
                };
                graph.restore_quarantine_record(record)?;
            }
        }
        graph.validate_edges()?;
        for revoked in &snapshot.revoked {
            let grant_id = GrantId::new(revoked.clone())?;
            let known = graph.grants.contains_key(&grant_id)
                || graph
                    .quarantined
                    .values()
                    .any(|relation| relation.child.grant_id == grant_id);
            if !known {
                return Err(AuthorityError::MissingParent(grant_id));
            }
            graph.revoked.insert(grant_id);
        }
        Ok(graph)
    }
}

fn grant_from_recovery_record(
    record: &GrantRecoveryRecord,
) -> Result<CapabilityGrant, AuthorityError> {
    Ok(CapabilityGrant {
        grant_id: GrantId::new(record.grant_id.clone())?,
        parent_grant_id: record
            .parent_grant_id
            .as_ref()
            .map(|id| GrantId::new(id.clone()))
            .transpose()?,
        authority_root_ref: record.authority_root_ref.clone(),
        issuer: PrincipalRef::new(record.issuer.clone())?,
        holder: PrincipalRef::new(record.holder.clone())?,
        authority: AuthoritySet::new(
            record.allowed_operations.clone(),
            record.allowed_resources.clone(),
            record.max_effect,
        )?,
        inherited_source_ceiling: record.inherited_source_ceiling,
        binding: record.binding.clone(),
        issued_at: LogicalTime::new(record.issued_at),
        expires_at: LogicalTime::new(record.expires_at),
        max_uses: record.max_uses,
        status: record.status,
    })
}

fn grant_to_recovery_record(grant: &CapabilityGrant) -> GrantRecoveryRecord {
    GrantRecoveryRecord {
        grant_id: grant.grant_id.as_str().to_owned(),
        parent_grant_id: grant
            .parent_grant_id
            .as_ref()
            .map(|id| id.as_str().to_owned()),
        authority_root_ref: grant.authority_root_ref.clone(),
        issuer: grant.issuer.as_str().to_owned(),
        holder: grant.holder.as_str().to_owned(),
        allowed_operations: grant.authority.operations().iter().cloned().collect(),
        allowed_resources: grant.authority.resources().iter().cloned().collect(),
        max_effect: grant.authority.max_effect(),
        inherited_source_ceiling: grant.inherited_source_ceiling,
        binding: grant.binding.clone(),
        issued_at: grant.issued_at.value(),
        expires_at: grant.expires_at.value(),
        max_uses: grant.max_uses,
        status: grant.status,
    }
}

/// Explicit non-authorizing disposition of a retained cross-root relation
/// (#2875 item 3). Quarantine is the only disposition such a relation can
/// carry: no authority consumer takes this type as an input, so a
/// quarantined relation is inert by construction while its full lineage
/// stays visible for audit and revocation reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CrossRootRelationDisposition {
    Quarantined,
}

/// One retained cross-root lineage record (#2875 items 3, 5, 8).
///
/// Cross-root influence represented separately from active authority
/// inheritance: exact source and dependent identities, both roots, owner
/// principals, the dependent's StateFence/Authority Epoch binding, the
/// revision the relation was quarantined at, and the deterministic relation
/// receipt. Quarantine is not deletion — the full dependent lineage is
/// retained — but retaining a record never admits it for authority: this
/// type is never placed in an [`EffectiveCapabilityPath`], a supporting
/// introduction ref, or the admitted grant map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedCrossRootRelation {
    /// Deterministic relation receipt for this exact edge.
    pub relation_id: String,
    /// Crossing source: the delegating parent grant.
    pub parent_grant_id: GrantId,
    /// Exact source root; the dependent root travels on `child`.
    pub parent_authority_root_ref: String,
    /// Full retained dependent lineage.
    pub child: CapabilityGrant,
    /// Graph revision the relation was quarantined at.
    pub quarantined_at_revision: u64,
    /// Always quarantined; the type is inert by construction.
    pub disposition: CrossRootRelationDisposition,
}

/// Deterministic wire form of one quarantined cross-root relation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuarantinedCrossRootRecord {
    pub relation_id: String,
    pub parent_grant_id: String,
    pub parent_authority_root_ref: String,
    pub child: GrantRecoveryRecord,
    pub quarantined_at_revision: u64,
    pub disposition: CrossRootRelationDisposition,
}

/// Migrates one lineage edge to an inert quarantined relation, retaining
/// the full dependent lineage. The edge must still be a narrowing: a
/// widening cross-root edge is not lineage and is refused.
fn migrate_to_quarantine(
    parent: &CapabilityGrant,
    child: &CapabilityGrant,
    revision: u64,
) -> Result<QuarantinedCrossRootRelation, AuthorityError> {
    check_narrowing(parent, child)?;
    Ok(QuarantinedCrossRootRelation {
        relation_id: quarantine_relation_id(&parent.grant_id, &child.grant_id),
        parent_grant_id: parent.grant_id.clone(),
        parent_authority_root_ref: parent.authority_root_ref.clone(),
        child: child.clone(),
        quarantined_at_revision: revision,
        disposition: CrossRootRelationDisposition::Quarantined,
    })
}

/// An independently valid path contributing to a holder snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveCapabilityPath {
    pub grant_path: Vec<GrantId>,
    pub authority: AuthoritySet,
}

/// Derived holder view. Authorization checks exact paths to avoid unsafe
/// cross-products between independent alternate paths. The graph constructs
/// snapshots and callers evaluate them through authorization query methods.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveCapabilitySnapshot {
    snapshot_id: SnapshotId,
    holder: PrincipalRef,
    work_scope: WorkScopeBinding,
    session: SessionBinding,
    grant_graph_revision: u64,
    paths: Vec<EffectiveCapabilityPath>,
}

impl EffectiveCapabilitySnapshot {
    pub fn allows(&self, operation: &str, resource: &str, effect: EffectClass) -> bool {
        self.paths
            .iter()
            .any(|path| path.authority.allows(operation, resource, effect))
    }

    pub fn has_supporting_grant(&self, grant_id: &GrantId) -> bool {
        self.paths
            .iter()
            .any(|path| path.grant_path.contains(grant_id))
    }

    pub fn validate_context(
        &self,
        work_scope: &WorkScopeBinding,
        session: &SessionBinding,
    ) -> Result<(), AuthorityError> {
        if self.work_scope.state_fence != work_scope.state_fence
            || self.session.state_fence != session.state_fence
            || work_scope.state_fence != session.state_fence
        {
            return Err(AuthorityError::FenceMismatch);
        }
        if !session
            .authority_epoch
            .is_same_authority(&session.state_fence.authority_epoch)
        {
            return Err(AuthorityError::EpochMismatch);
        }
        Ok(())
    }
}

/// One delegated member reference in a Governor-enumerated closure.
///
/// Identity and parent linkage only: semantic intents, opaque records, and
/// fence contours are served by the hydration layer from canonical state, not
/// by the pure graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantClosureMemberRef {
    /// Enumerated grant identity.
    pub grant_id: GrantId,
    /// Delegating parent identity. `None` only for the closure target when
    /// the target is itself an authority root.
    pub parent_grant_id: Option<GrantId>,
}

/// Owner-enumerated descendant closure of one grant at one graph revision.
///
/// Returned by [`GrantGraph::delegated_closure`]: the complete affected set
/// the Kernel fences for a delegation revocation, with the revision it was
/// read at. Survivor paths on independent authority lines are declared by
/// the hydration layer, never inferred here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantClosureDelegation {
    /// Lineage domain shared by every member.
    pub authority_root_ref: String,
    /// Graph revision the closure was enumerated at.
    pub revision: u64,
    /// Closure members in parent-before-child order, target first.
    pub members: Vec<GrantClosureMemberRef>,
}

/// Legacy projection of a receipt-authorized cross-root descendant.
///
/// Current construction and recovery admit no transition receipts, so this
/// projection is empty. A future trusted issuer would need to bind the
/// identity before this projection could enter a complete verdict consumed
/// by the durable fencing owner (#2100).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCrossRootMember {
    /// Enumerated grant identity.
    pub grant_id: GrantId,
    /// Delegating parent identity; always present on a crossing path.
    pub parent_grant_id: GrantId,
    /// The member's own authority root.
    pub authority_root_ref: String,
    /// Exact admitted receipt authorizing the nearest crossing above this
    /// member (its own edge when the member itself crosses).
    pub authorizing_transition_id: String,
}

/// One quarantined cross-root dependent encountered by a closure.
///
/// The dependent authorizes nothing, and the traversal stops at it. The
/// verdict retains its local quarantine relation ID as evidence; the ID has
/// no owner verification and is not proof. This frontier forces
/// `PartialOrUnknown`, which the durable fencing owner (#2100) will not accept
/// as complete coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedFrontierMember {
    /// Quarantined dependent identity.
    pub grant_id: GrantId,
    /// Crossing source identity.
    pub parent_grant_id: GrantId,
    /// Retained quarantine relation ID for this edge; owner verification is pending.
    pub relation_id: String,
}

/// Honest revocation-closure state (#2875 item 6).
///
/// `Complete` requires exact agreement with the structural denominator and
/// no unresolved frontier or engine omissions. Local quarantine relation IDs
/// are evidence only; they never make a cross-root omission complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationClosureState {
    /// The affected denominator matches the structural walk with no
    /// unresolved omitted dependent.
    Complete { separately_quarantined: Vec<String> },
    /// Recovery-required: the exact unresolved frontier plus the exact
    /// engine omissions in engine order. Retained quarantine relation IDs
    /// travel alongside as evidence only, so partial progress stays auditable.
    PartialOrUnknown {
        frontier: Vec<String>,
        omissions: Vec<RevocationOmission>,
        separately_quarantined: Vec<String>,
    },
}

/// Typed revocation-closure verdict: a complete denominator or an explicit
/// partial/unknown state, never an omission-labelled success.
///
/// Package-level verdict with the same-root denominator, quarantined
/// frontier, and completeness state reconciling the bounded engine outcome
/// against the live graph. The durable descendant-closure fencing owner
/// (#2100) consumes `Complete` for durable fencing. Local quarantine relation
/// IDs remain evidence only and cannot make a cross-root omission complete.
/// Legacy transition fields remain empty because this module admits no
/// unverified root-transition receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationClosureVerdict {
    /// Revoked origin.
    pub origin: GrantId,
    /// Graph revision the verdict was computed at.
    pub revision: u64,
    /// Origin authority root.
    pub authority_root_ref: String,
    /// Same-root denominator in parent-before-child order with the target
    /// first; element-wise equal to [`GrantGraph::delegated_closure`].
    pub members: Vec<GrantClosureMemberRef>,
    /// Legacy projection for receipt-authorized cross-root descendants;
    /// empty because this module has no trusted receipt verifier.
    pub authorized_cross_root: Vec<AuthorizedCrossRootMember>,
    /// Quarantined dependents encountered with bound receipts.
    pub quarantined_frontier: Vec<QuarantinedFrontierMember>,
    /// Legacy projection of followed transition receipt IDs; empty because
    /// this module admits no unverified transition receipts.
    pub traversed_transitions: Vec<String>,
    /// Honest completeness state of this closure.
    pub state: RevocationClosureState,
}

/// `ELIOT_ARCH_OWNER`: ARCH-AUTH-01
/// Pure grant-lineage evaluator.
#[derive(Clone, Debug)]
pub struct GrantGraph {
    grants: BTreeMap<GrantId, CapabilityGrant>,
    revoked: BTreeSet<GrantId>,
    revision: u64,
    transitions: BTreeMap<(GrantId, GrantId), RootTransitionReceipt>,
    quarantined: BTreeMap<String, QuarantinedCrossRootRelation>,
}

impl GrantGraph {
    /// Constructs a graph of ordinary same-root delegation (#2875 items 1,
    /// 2). A child whose `authority_root_ref` differs from its parent's is
    /// rejected with [`AuthorityError::GrantNotNarrower`]; this module has no
    /// trusted root-transition issuer or verifier that could authorize it.
    pub fn from_grants(
        grants: impl IntoIterator<Item = CapabilityGrant>,
        revision: u64,
    ) -> Result<Self, AuthorityError> {
        Self::from_grants_with_transitions(grants, Vec::new(), revision)
    }

    /// Compatibility entry point for callers that still provide claimed
    /// root-transition receipts (#2875 item 4). Nonempty receipt input is
    /// rejected with `InvalidField("root_transition_receipt.owner_issuance_unverified")`:
    /// this module has no production owner issuer or verifier, and field
    /// equality alone is not authority. Empty input has the same semantics as
    /// [`GrantGraph::from_grants`].
    pub fn from_grants_with_transitions(
        grants: impl IntoIterator<Item = CapabilityGrant>,
        transitions: impl IntoIterator<Item = RootTransitionReceipt>,
        revision: u64,
    ) -> Result<Self, AuthorityError> {
        if transitions.into_iter().next().is_some() {
            return Err(AuthorityError::InvalidField(
                "root_transition_receipt.owner_issuance_unverified",
            ));
        }
        if revision == 0 {
            return Err(AuthorityError::InvalidField("grant_graph_revision"));
        }
        let mut by_id = BTreeMap::new();
        for grant in grants {
            grant.validate_local()?;
            let grant_id = grant.grant_id.clone();
            if by_id.insert(grant_id.clone(), grant).is_some() {
                return Err(AuthorityError::DuplicateGrant(grant_id));
            }
        }
        let graph = Self {
            grants: by_id,
            revoked: BTreeSet::new(),
            revision,
            transitions: BTreeMap::new(),
            quarantined: BTreeMap::new(),
        };
        graph.validate_cycles()?;
        graph.validate_edges()?;
        Ok(graph)
    }

    /// Stored transition receipt for one delegation edge, if present. This
    /// module's public constructor and restore paths currently admit none.
    pub fn transition_for_edge(
        &self,
        parent: &GrantId,
        child: &GrantId,
    ) -> Option<&RootTransitionReceipt> {
        self.transitions.get(&(parent.clone(), child.clone()))
    }

    /// Quarantine relation retained for one exact edge, if that edge was
    /// migrated or restored as quarantined evidence.
    pub fn quarantine_for_edge(
        &self,
        parent: &GrantId,
        child: &GrantId,
    ) -> Option<&QuarantinedCrossRootRelation> {
        self.quarantined.values().find(|relation| {
            &relation.parent_grant_id == parent && relation.child.grant_id == *child
        })
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns every grant id in deterministic grant-id order.
    pub(crate) fn ordered_grant_ids(&self) -> Vec<String> {
        self.grants
            .keys()
            .map(|id| id.as_str().to_owned())
            .collect()
    }

    /// Returns one grant by its string identity.
    pub(crate) fn grant(&self, grant_id: &str) -> Option<&CapabilityGrant> {
        let id = GrantId::new(grant_id).ok()?;
        self.grants.get(&id)
    }

    /// Marks one grant revoked without replaying history.
    pub(crate) fn apply_restored_revocation(&mut self, grant_id: &GrantId) {
        self.revoked.insert(grant_id.clone());
    }

    /// Emits the complete durable graph: admitted authority, revoked set,
    /// the empty legacy transition-receipt section, and inert quarantined
    /// relations. A quarantined relation re-emits into the quarantine section only, so
    /// snapshot/recovery/restart preserve the quarantine invariant and can
    /// never reactivate a legacy cross-root child as active authority.
    pub fn recovery_snapshot(&self) -> Result<GrantGraphRecoverySnapshot, AuthorityError> {
        let grants = self.grants.values().map(grant_to_recovery_record).collect();
        let mut root_transitions: Vec<RootTransitionReceipt> =
            self.transitions.values().cloned().collect();
        root_transitions.sort_by(|left, right| left.transition_id.cmp(&right.transition_id));
        let quarantined_cross_root = self
            .quarantined
            .values()
            .map(|relation| QuarantinedCrossRootRecord {
                relation_id: relation.relation_id.clone(),
                parent_grant_id: relation.parent_grant_id.as_str().to_owned(),
                parent_authority_root_ref: relation.parent_authority_root_ref.clone(),
                child: grant_to_recovery_record(&relation.child),
                quarantined_at_revision: relation.quarantined_at_revision,
                disposition: relation.disposition,
            })
            .collect();
        let snapshot = GrantGraphRecoverySnapshot {
            schema: GRANT_GRAPH_RECOVERY_SCHEMA.to_owned(),
            version: GRANT_GRAPH_RECOVERY_VERSION,
            revision: self.revision,
            grants,
            revoked: self
                .revoked
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
            root_transitions,
            quarantined_cross_root,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn from_recovery_snapshot(
        snapshot: &GrantGraphRecoverySnapshot,
    ) -> Result<Self, AuthorityError> {
        snapshot.validate_wire()?;
        GrantGraphRecoverySnapshot::restore_owned(snapshot)
    }

    /// Restores a recovery snapshot under explicit CURRENT revocation-history
    /// evidence, applying all applicable committed revocations before any
    /// grant becomes effective.
    ///
    /// `None` history refuses with
    /// [`RevocationHistoryError::MissingHistory`]: unavailable history is
    /// not absence of revocation and never restores as an empty closure.
    /// Stale (fence or revision drift) and unknown (invalid, unordered, or
    /// non-revoked closure) evidence refuse likewise. Suppressed grants are
    /// retained with their full lineage and join the restored revoked set,
    /// so neither a revoked origin nor its dependent grants can revive; the
    /// exact suppressed set and reasons are reported in the outcome.
    /// Unrelated valid grants restore exactly as the snapshot carries them.
    ///
    /// The production recheck refuses by named cause through
    /// [`RevocationHistoryError::BoundedRevocation`], so a caller can tell the
    /// four failure classes apart instead of reading one untyped refusal:
    /// [`UnsupportedSchema`](eliot_influence::InfluenceError::UnsupportedSchema)
    /// for a snapshot whose declared schema or version is not the supported one
    /// (decided before any other wire field is validated),
    /// [`UnverifiedRecovery`](eliot_influence::InfluenceError::UnverifiedRecovery)
    /// for a committed closure whose declared origin this graph cannot relate to
    /// its own lineage while the closure still names in-graph targets,
    /// [`IncompleteCoverage`](eliot_influence::InfluenceError::IncompleteCoverage)
    /// when the bounded evaluator could not prove the whole dependent closure
    /// inside the declared bounds, and
    /// [`TargetDrift`](eliot_influence::InfluenceError::TargetDrift) when the
    /// closure recomputed from the live graph reaches an in-graph target the
    /// committed closure does not name. The first, third, and fourth of these
    /// refused before this change as well, under `InvalidSnapshot` or the
    /// untyped `UnknownHistory`; only the cause is named there. The second is a
    /// strictly new refusal: a foreign-origin closure naming in-graph targets
    /// used to restore unrecheckable, and now refuses. Separately, this
    /// issue's fail-closed root boundary rejects snapshots carrying unverified
    /// transition receipts before any grant is restored.
    ///
    /// The legacy [`from_recovery_snapshot`](Self::from_recovery_snapshot)
    /// preserves its exact prior behavior for previously-admitted callers.
    pub fn from_recovery_snapshot_with_revocation_history(
        snapshot: &GrantGraphRecoverySnapshot,
        history: Option<&crate::RevocationHistoryEvidence>,
    ) -> Result<GrantRestoreOutcome, RevocationHistoryError> {
        // Schema identity is decided before any other wire field is validated,
        // so a snapshot persisted under an unsupported revision refuses by
        // cause instead of being read as if its protected fields had been
        // defaulted. The two checks below are the same refusals `validate_wire`
        // still makes; running them first only names the cause.
        if snapshot.schema != GRANT_GRAPH_RECOVERY_SCHEMA {
            return Err(RevocationHistoryError::BoundedRevocation(
                eliot_influence::InfluenceError::UnsupportedSchema("grant_graph_recovery.schema"),
            ));
        }
        if snapshot.version != GRANT_GRAPH_RECOVERY_VERSION {
            return Err(RevocationHistoryError::BoundedRevocation(
                eliot_influence::InfluenceError::UnsupportedSchema("grant_graph_recovery.version"),
            ));
        }
        snapshot
            .validate_wire()
            .map_err(RevocationHistoryError::InvalidSnapshot)?;
        let evidence = history.ok_or(RevocationHistoryError::MissingHistory)?;
        let closures = evidence.require_current()?;
        let mut graph = GrantGraphRecoverySnapshot::restore_owned(snapshot)
            .map_err(RevocationHistoryError::InvalidSnapshot)?;
        for grant_id in graph.ordered_grant_ids() {
            let Some(grant) = graph.grant(&grant_id) else {
                continue;
            };
            if grant.binding.state_fence != evidence.state_fence {
                return Err(RevocationHistoryError::StaleHistory);
            }
        }
        let suppressed = derive_suppressions(&graph, &closures);
        // Fail-closed recheck: every verdict-reachable in-graph descendant
        // of an affected in-graph grant must already be suppressed. The
        // verdict reconciles the bounded engine outcome against the live
        // graph: it follows admitted parent links (currently same-root),
        // preserves each omitted cross-root dependent in the frontier and
        // any matching local relation ID as evidence, then reports the
        // verdict as partial/unknown — so a partial verdict, or a closure that
        // under-claims its transitive descendants, still refuses. Without an
        // owner-verified quarantine receipt, every omitted cross-root
        // dependent remains unresolved whether or not a local relation ID is
        // bound. Affected references naming no grant in this graph belong to
        // another graph's denominator and refuse nothing.
        let suppressed_ids: BTreeSet<&str> = suppressed
            .iter()
            .map(|entry| entry.grant_id.as_str())
            .collect();
        for closure in &closures {
            Self::recheck_committed_closure(
                &graph,
                closure,
                &evidence.state_fence,
                &suppressed_ids,
            )?;
        }
        for entry in &suppressed {
            if let Ok(grant_id) = GrantId::new(entry.grant_id.clone()) {
                graph.apply_restored_revocation(&grant_id);
            }
        }
        Ok(GrantRestoreOutcome { graph, suppressed })
    }

    /// Fail-closed recheck of one committed revocation closure against the
    /// restored graph, naming the cause of every refusal.
    ///
    /// Three decisions, all reached from
    /// [`from_recovery_snapshot_with_revocation_history`](Self::from_recovery_snapshot_with_revocation_history):
    ///
    /// 1. the closure's declared origin must be relatable to this graph's own
    ///    lineage, because `derive_suppressions` will revoke the in-graph
    ///    targets the closure names and an origin outside the graph cannot be
    ///    rechecked against live lineage. An in-graph grant origin and an
    ///    authority-root origin both stay admissible, and a closure naming no
    ///    in-graph grant still refuses nothing. This is the A0.3 hard boundary
    ///    "restoration of revoked influence after recovery" refused by cause
    ///    instead of accepted unrecheckable;
    /// 2. the bounded evaluator must prove the whole dependent closure inside
    ///    the declared bounds, otherwise the affected set is a bounded prefix
    ///    and I15.7's explicit incomplete-coverage refusal applies;
    /// 3. every in-graph grant the verdict can reach (currently same-root;
    ///    the legacy cross-root member projection is empty) must already be suppressed,
    ///    otherwise the committed closure under-claims its transitive
    ///    descendants and the stored target set drifted.
    ///
    /// The recheck reads the verdict owner, not the bounded engine directly:
    /// [`GrantGraph::revocation_closure_verdict`] reconciles the engine outcome
    /// against the live graph, follows admitted same-root parent links,
    /// preserves omitted cross-root dependents in the exact frontier, and
    /// retains matching local quarantine IDs as evidence before reporting
    /// [`RevocationClosureState::PartialOrUnknown`]. A local ID is not an
    /// owner-verified receipt, so every cross-root omission remains partial;
    /// a missing ID is also preserved in the frontier.
    ///
    /// An affected reference naming no grant in this graph belongs to another
    /// graph's denominator and refuses nothing.
    fn recheck_committed_closure(
        graph: &GrantGraph,
        closure: &crate::revocation_history::ValidatedRevocationClosure,
        fence: &StateFence,
        suppressed_ids: &BTreeSet<&str>,
    ) -> Result<(), RevocationHistoryError> {
        let origin_is_local = graph.grant(closure.root_ref.as_str()).is_some()
            || graph
                .grants
                .values()
                .any(|grant| grant.authority_root_ref == closure.root_ref);
        if !origin_is_local
            && closure
                .affected
                .iter()
                .any(|reference| graph.grant(reference.as_str()).is_some())
        {
            return Err(RevocationHistoryError::BoundedRevocation(
                eliot_influence::InfluenceError::UnverifiedRecovery("recovery.closure_origin"),
            ));
        }
        for affected_ref in &closure.affected {
            let Ok(grant_id) = GrantId::new(affected_ref.as_str()) else {
                continue;
            };
            if graph.grant(grant_id.as_str()).is_none() {
                continue;
            }
            let verdict = graph
                .revocation_closure_verdict(
                    &grant_id,
                    fence,
                    &eliot_influence::RevocationBounds::default_bounds(),
                )
                .map_err(map_bounded_history_error)?;
            // The verdict has exactly two states, so a non-`Complete` verdict IS
            // the incomplete-coverage cause: the closure could not be proven
            // whole inside the declared bounds, or a cross-root omission
            // remains partial because a retained local relation ID is not
            // verified owner evidence.
            if !matches!(verdict.state, RevocationClosureState::Complete { .. }) {
                return Err(RevocationHistoryError::BoundedRevocation(
                    eliot_influence::InfluenceError::IncompleteCoverage("recovery.closure_verdict"),
                ));
            }
            let denied = verdict
                .members
                .iter()
                .map(|member| member.grant_id.as_str())
                .chain(
                    verdict
                        .authorized_cross_root
                        .iter()
                        .map(|member| member.grant_id.as_str()),
                )
                .any(|denied_ref| {
                    graph.grant(denied_ref).is_some() && !suppressed_ids.contains(denied_ref)
                });
            if denied {
                return Err(RevocationHistoryError::BoundedRevocation(
                    eliot_influence::InfluenceError::TargetDrift("recovery.closure_affected"),
                ));
            }
        }
        Ok(())
    }

    pub fn revoke(&mut self, grant_id: &GrantId) -> Result<(), AuthorityError> {
        if !self.grants.contains_key(grant_id) {
            return Err(AuthorityError::MissingParent(grant_id.clone()));
        }
        self.revoked.insert(grant_id.clone());
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::InvalidField("grant_graph_revision"))?;
        Ok(())
    }

    /// Enumerates the exact descendant closure of one grant at the current
    /// graph revision: the target plus every transitive child on the same
    /// authority root, in parent-before-child order with the target first.
    ///
    /// This is the Governor-side lineage primitive behind durable closure
    /// revocation (`#2100`): the graph owner declares the complete affected
    /// set so the Kernel never fences from caller material or process memory
    /// alone. Lineage that crosses roots is never followed. The traversal is
    /// defended with a visited set, so it terminates even on a graph that
    /// was not validated at construction. Revoked grants are still listed:
    /// revocation status is enforcement state, not lineage shape, and the
    /// caller decides the fence disposition.
    ///
    /// Alternate-path survival is not decided here: grants on independent
    /// authority paths are separate graph entries, and the surviving-path
    /// declaration belongs to the hydration layer that serves the full
    /// closure evidence.
    ///
    /// The legacy cross-root descendant projection and quarantined dependents
    /// are enumerated separately by
    /// [`revocation_closure_verdict`](Self::revocation_closure_verdict),
    /// but the descendant projection is empty without a trusted transition
    /// issuer. The durable fencing owner (#2100) consumes the verdict's
    /// completeness state; quarantined relation IDs remain evidence in its
    /// partial frontier, not verified receipts.
    pub fn delegated_closure(
        &self,
        grant_id: &GrantId,
    ) -> Result<GrantClosureDelegation, AuthorityError> {
        let target = self
            .grants
            .get(grant_id)
            .ok_or_else(|| AuthorityError::MissingParent(grant_id.clone()))?;
        let authority_root_ref = target.authority_root_ref.clone();
        let mut members = vec![GrantClosureMemberRef {
            grant_id: target.grant_id.clone(),
            parent_grant_id: target.parent_grant_id.clone(),
        }];
        let mut seen = BTreeSet::new();
        seen.insert(target.grant_id.clone());
        let mut frontier = vec![target.grant_id.clone()];
        while let Some(current) = frontier.pop() {
            // Grant-id order keeps the enumeration deterministic across
            // restarts and owners.
            let mut children: Vec<&CapabilityGrant> = self
                .grants
                .values()
                .filter(|grant| {
                    grant.parent_grant_id.as_ref() == Some(&current)
                        && !crosses_authority_root(&grant.authority_root_ref, &authority_root_ref)
                })
                .collect();
            children.sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
            for child in children {
                if !seen.insert(child.grant_id.clone()) {
                    continue;
                }
                frontier.push(child.grant_id.clone());
                members.push(GrantClosureMemberRef {
                    grant_id: child.grant_id.clone(),
                    parent_grant_id: child.parent_grant_id.clone(),
                });
            }
        }
        // Discovery order is already parent-before-child: a child is
        // recorded only when its parent is popped. Siblings pop in reverse
        // grant-id order from the stack, which is still deterministic across
        // restarts and owners.
        Ok(GrantClosureDelegation {
            authority_root_ref,
            revision: self.revision,
            members,
        })
    }

    /// Partitions a restored full map into admitted authority and migrated
    /// quarantine (#2875 item 9). Roots admit; a grant whose parent edge is
    /// authorized (same-root or receipt-covered) and whose parent admitted
    /// admits with it; anything else — an unauthorized crossing or a
    /// descendant below one — migrates to an inert quarantined relation
    /// with its full lineage retained. Deterministic fixpoint over
    /// grant-id order: exact replay restores the exact same partition. A
    /// collision in the legacy delimiter-joined quarantine label fails with
    /// `IdentityConflict`, preserving both children instead of overwriting.
    fn partition_restored(mut self) -> Result<Self, AuthorityError> {
        let mut admitted: BTreeMap<GrantId, CapabilityGrant> = BTreeMap::new();
        let mut quarantined_ids: BTreeSet<GrantId> = BTreeSet::new();
        for (id, grant) in &self.grants {
            if grant.parent_grant_id.is_none() {
                admitted.insert(id.clone(), grant.clone());
            }
        }
        loop {
            let mut progressed = false;
            for (id, grant) in &self.grants {
                if admitted.contains_key(id) || quarantined_ids.contains(id) {
                    continue;
                }
                let Some(parent_id) = grant.parent_grant_id.as_ref() else {
                    continue;
                };
                let Some(parent) = self.grants.get(parent_id) else {
                    return Err(AuthorityError::MissingParent(parent_id.clone()));
                };
                if quarantined_ids.contains(parent_id) {
                    let relation = migrate_to_quarantine(parent, grant, self.revision)?;
                    if self.quarantined.contains_key(&relation.relation_id) {
                        return Err(AuthorityError::IdentityConflict);
                    }
                    quarantined_ids.insert(id.clone());
                    self.quarantined
                        .insert(relation.relation_id.clone(), relation);
                    progressed = true;
                } else if admitted.contains_key(parent_id) {
                    if edge_is_authorized(parent, grant, &self.transitions) {
                        admitted.insert(id.clone(), grant.clone());
                    } else {
                        let relation = migrate_to_quarantine(parent, grant, self.revision)?;
                        if self.quarantined.contains_key(&relation.relation_id) {
                            return Err(AuthorityError::IdentityConflict);
                        }
                        quarantined_ids.insert(id.clone());
                        self.quarantined
                            .insert(relation.relation_id.clone(), relation);
                    }
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        // Acyclic parents resolve every grant: anything left refuses rather
        // than silently dropping lineage.
        if admitted.len() + quarantined_ids.len() != self.grants.len() {
            return Err(AuthorityError::InvalidField(
                "grant_graph_recovery.partition",
            ));
        }
        self.grants = admitted;
        Ok(self)
    }

    /// Restores one explicit quarantined record as inert evidence only. The
    /// record must preserve the exact parent root and narrow its parent. A
    /// cross-root edge is quarantined under any parent; a same-root edge is
    /// accepted only below an already-quarantined parent. Parents resolve in
    /// the admitted map or previously restored quarantine, so recovery order
    /// preserves lineage and cannot quarantine an ordinary admitted child.
    fn restore_quarantine_record(
        &mut self,
        record: &QuarantinedCrossRootRecord,
    ) -> Result<(), AuthorityError> {
        validate_text(&record.relation_id, "quarantined_cross_root.relation_id")?;
        validate_text(
            &record.parent_authority_root_ref,
            "quarantined_cross_root.root",
        )?;
        if record.quarantined_at_revision == 0 || record.quarantined_at_revision > self.revision {
            return Err(AuthorityError::InvalidField(
                "quarantined_cross_root.revision",
            ));
        }
        let parent_id = GrantId::new(record.parent_grant_id.clone())?;
        let child = grant_from_recovery_record(&record.child)?;
        child.validate_local()?;
        if child.parent_grant_id.as_ref() != Some(&parent_id) {
            return Err(AuthorityError::InvalidField("quarantined_cross_root.edge"));
        }
        if self.grants.contains_key(&child.grant_id) {
            return Err(AuthorityError::IdentityConflict);
        }
        if self
            .quarantined
            .values()
            .any(|known| known.child.grant_id == child.grant_id)
        {
            return Err(AuthorityError::IdentityConflict);
        }
        let quarantined_parent = self
            .quarantined
            .values()
            .find(|known| known.child.grant_id == parent_id)
            .map(|known| &known.child);
        let (parent, parent_is_quarantined): (&CapabilityGrant, bool) =
            if let Some(parent) = self.grants.get(&parent_id) {
                (parent, false)
            } else if let Some(parent) = quarantined_parent {
                (parent, true)
            } else {
                return Err(AuthorityError::MissingParent(parent_id.clone()));
            };
        if parent.authority_root_ref != record.parent_authority_root_ref {
            return Err(AuthorityError::InvalidField("quarantined_cross_root.root"));
        }
        if !crosses_authority_root(&parent.authority_root_ref, &child.authority_root_ref)
            && !parent_is_quarantined
        {
            return Err(AuthorityError::InvalidField("quarantined_cross_root.edge"));
        }
        check_narrowing(parent, &child)?;
        if self.quarantined.contains_key(&record.relation_id) {
            return Err(AuthorityError::IdentityConflict);
        }
        let relation = QuarantinedCrossRootRelation {
            relation_id: record.relation_id.clone(),
            parent_grant_id: parent_id,
            parent_authority_root_ref: record.parent_authority_root_ref.clone(),
            child,
            quarantined_at_revision: record.quarantined_at_revision,
            disposition: record.disposition,
        };
        self.quarantined
            .insert(relation.relation_id.clone(), relation);
        Ok(())
    }

    /// Recomputes the exact transitive revocation closure of one grant
    /// through the pure `eliot-influence` bounded revocation evaluator.
    ///
    /// This is a read-only recheck of a complete, current closure against
    /// the same origin, scope, fence, and snapshot: the caller supplies the
    /// origin grant, the recovery fence, and explicit bounds, and the engine
    /// derives the exact affected set from live-graph delegation edges.
    /// Historical drift is rejected earlier at `require_current` plus the
    /// fence checks in
    /// [`from_recovery_snapshot_with_revocation_history`](Self::from_recovery_snapshot_with_revocation_history);
    /// this method evaluates the current live graph only.
    ///
    /// Every authorized same-root delegation edge becomes one qualified
    /// influence edge with
    /// [`PermittedCurrent`](InfluenceEdgeDisposition::PermittedCurrent)
    /// disposition: authorized live-graph edges are current by
    /// construction. This module cannot verify root-transition issuance, so
    /// cross-root edges are not authorized inheritance. Such an edge — and
    /// every retained
    /// [`QuarantinedCrossRootRelation`] — is declared with the dedicated
    /// cross-scope influence relation
    /// ([`QualifiedInfluenceEdge::cross_scope`]), so the evaluator records
    /// a typed cross-scope omission naming the exact source-bound edge
    /// position instead of the link vanishing from the denominator. Such a
    /// dependent is never followed, never revoked by this traversal, and
    /// never part of the affected set, mirroring
    /// [`delegated_closure`](Self::delegated_closure) and the rule that
    /// revocation cannot widen scope.
    ///
    /// The engine's `complete` flag means the traversal finished within
    /// bounds; it does not reconcile omissions. Authority consumers must
    /// use [`revocation_closure_verdict`](Self::revocation_closure_verdict),
    /// which preserves each omitted dependent in the exact frontier and its
    /// engine omission. A local quarantine relation ID is retained as
    /// evidence only and still yields partial/unknown.
    ///
    /// The production recheck runs the evaluator in bounded pages and resumes
    /// only from the exact returned continuation. Per-page limits may end a
    /// call early, but the caller-supplied operation-global bounds, graph/fence
    /// binding, cumulative work, and pending source-edge position remain
    /// unchanged across every page. A global-bound refusal remains incomplete
    /// and is never converted to a clear traversal.
    ///
    /// Historical grants and lineage are preserved: this method takes
    /// `&self` and deletes nothing. The graph crate never mutates
    /// authority; this crate calls the pure evaluator only and preserves its
    /// typed refusal through [`AuthorityError::BoundedRevocation`].
    pub fn transitive_revocation_closure(
        &self,
        origin: &GrantId,
        fence: &StateFence,
        bounds: &eliot_influence::RevocationBounds,
    ) -> Result<eliot_influence::BoundedRevocationOutcome, AuthorityError> {
        if !self.grants.contains_key(origin) {
            return Err(AuthorityError::MissingParent(origin.clone()));
        }
        // `BTreeMap` iteration is grant-id ordered, so edge order is
        // deterministic across restarts and owners.
        let mut edges = Vec::new();
        for grant in self.grants.values() {
            let Some(parent_id) = grant.parent_grant_id.as_ref() else {
                // A grant with no parent grant id is a delegation root, not an
                // edge: it has no source position to qualify, so there is no
                // edge to declare and no disposition to record for it here.
                continue;
            };
            let Some(parent) = self.grants.get(parent_id) else {
                // Admitted maps resolve every parent; an unresolvable edge
                // is declared cross-scope so the evaluator records a typed
                // omission for it instead of following unknown lineage.
                edges.push(QualifiedInfluenceEdge::cross_scope(
                    parent_id.as_str().to_owned(),
                    grant.grant_id.as_str().to_owned(),
                ));
                continue;
            };
            // Authorized inheritance — same-root or receipt-covered — is
            // current by construction and propagates. Anything else is
            // declared with the dedicated cross-scope influence relation so
            // the evaluator records a typed `CrossScope` omission naming the
            // exact source-bound edge position instead of an absent edge the
            // reader cannot distinguish from an unexamined one. Revocation
            // cannot widen scope or effect: an omitted dependent is never
            // followed, never revoked by this traversal, and never enters
            // the affected set.
            if edge_is_authorized(parent, grant, &self.transitions) {
                edges.push(QualifiedInfluenceEdge {
                    source_ref: parent_id.as_str().to_owned(),
                    dependent_ref: grant.grant_id.as_str().to_owned(),
                    disposition: InfluenceEdgeDisposition::PermittedCurrent,
                });
            } else {
                edges.push(QualifiedInfluenceEdge::cross_scope(
                    parent_id.as_str().to_owned(),
                    grant.grant_id.as_str().to_owned(),
                ));
            }
        }
        // Retained quarantined relations are influence evidence, not
        // authority: each is declared with the dedicated cross-scope
        // relation so the omission names the exact refused edge while the
        // full lineage stays visible in the snapshot. Quarantine is not
        // erasure; the verdict preserves the omitted dependent and omission,
        // retaining the relation ID only as local evidence without owner
        // verification.
        for relation in self.quarantined.values() {
            edges.push(QualifiedInfluenceEdge::cross_scope(
                relation.parent_grant_id.as_str().to_owned(),
                relation.child.grant_id.as_str().to_owned(),
            ));
        }
        let request = BoundedRevocationRequest {
            request_id: format!("transitive-revocation:{}", origin.as_str()),
            root_ref: origin.as_str().to_owned(),
            reason: RevocationReason::SourceRevoked,
            state_fence: fence.clone(),
            edges,
            completeness: ClosureCompleteness::Complete,
            resumed_visited: Vec::new(),
        };
        let page_limits = eliot_influence::BoundedRevocationPageLimits {
            max_page_edges: bounds.max_edges.min(REVOCATION_PAGE_EDGE_LIMIT),
            max_page_work: bounds.max_work.min(REVOCATION_PAGE_WORK_LIMIT),
        };
        let mut outcome = eliot_influence::revoke_bounded_page(&request, bounds, page_limits)
            .map_err(map_bounded_revocation_error)?;
        while !outcome.complete {
            if outcome.omissions.iter().any(|omission| {
                matches!(
                    omission.cause,
                    eliot_influence::OmissionCause::BoundsExhausted
                )
            }) {
                break;
            }
            let continuation = outcome
                .continuation
                .clone()
                .ok_or(AuthorityError::InvalidField(
                    "transitive_revocation_closure",
                ))?;
            let continuation_token =
                outcome
                    .continuation_token()
                    .cloned()
                    .ok_or(AuthorityError::InvalidField(
                        "transitive_revocation_closure",
                    ))?;
            let previous_work = outcome.work_spent;
            outcome = eliot_influence::resume_bounded_revocation(
                &request,
                &continuation,
                &continuation_token,
                bounds,
                page_limits,
            )
            .map_err(map_bounded_revocation_error)?;
            if !outcome.complete
                && outcome.work_spent == previous_work
                && !outcome.omissions.iter().any(|omission| {
                    matches!(
                        omission.cause,
                        eliot_influence::OmissionCause::BoundsExhausted
                    )
                })
            {
                return Err(AuthorityError::InvalidField(
                    "transitive_revocation_closure",
                ));
            }
        }
        Ok(outcome)
    }

    /// Collects quarantined dependents whose edge source the walk reached.
    /// The durable fencing owner (#2100) consumes the verdict's completeness
    /// state; these local relation IDs remain frontier evidence, not receipts.
    fn collect_quarantined_frontier(
        &self,
        reached: &BTreeSet<String>,
    ) -> Vec<QuarantinedFrontierMember> {
        let mut quarantined_frontier = Vec::new();
        for relation in self.quarantined.values() {
            if reached.contains(relation.parent_grant_id.as_str()) {
                quarantined_frontier.push(QuarantinedFrontierMember {
                    grant_id: relation.child.grant_id.clone(),
                    parent_grant_id: relation.parent_grant_id.clone(),
                    relation_id: relation.relation_id.clone(),
                });
            }
        }
        quarantined_frontier
    }

    /// Reconciles one bounded engine outcome against the structural walk
    /// (#2875 item 6): the engine's affected set must match the reached set
    /// exactly, while every cross-root omission remains partial even when its
    /// local quarantine relation ID is retained as evidence. A quarantined
    /// frontier absent from engine omissions also forces partial/unknown.
    /// Returns exact frontier refs, retained relation IDs, and completeness.
    fn reconcile_engine_outcome(
        &self,
        outcome: &eliot_influence::BoundedRevocationOutcome,
        reached: &BTreeSet<String>,
        unbound: BTreeSet<String>,
        quarantined_frontier: &[QuarantinedFrontierMember],
    ) -> (BTreeSet<String>, BTreeSet<String>, bool) {
        let mut frontier_refs: BTreeSet<String> = outcome.frontier.iter().cloned().collect();
        let mut separately_quarantined: BTreeSet<String> = BTreeSet::new();
        let mut partial = !outcome.complete
            || !outcome.frontier.is_empty()
            || !unbound.is_empty()
            || !quarantined_frontier.is_empty();
        frontier_refs.extend(unbound);
        frontier_refs.extend(
            quarantined_frontier
                .iter()
                .map(|member| member.grant_id.as_str().to_owned()),
        );
        let mut affected: BTreeSet<String> = BTreeSet::new();
        for affected_ref in &outcome.affected_refs {
            let Ok(grant_id) = GrantId::new(affected_ref.as_str()) else {
                frontier_refs.insert(affected_ref.clone());
                partial = true;
                continue;
            };
            if !self.grants.contains_key(&grant_id) {
                frontier_refs.insert(affected_ref.clone());
                partial = true;
                continue;
            }
            affected.insert(affected_ref.clone());
        }
        // The engine must agree with the structural walk: revocation
        // traversal and authority enumeration cannot hold different
        // denominators for one origin.
        for missing in reached.symmetric_difference(&affected) {
            frontier_refs.insert(missing.clone());
            partial = true;
        }
        for omission in &outcome.omissions {
            match omission.cause {
                OmissionCause::BoundsExhausted => {
                    partial = true;
                }
                OmissionCause::CrossScope => {
                    frontier_refs.insert(omission.edge_dependent.clone());
                    partial = true;
                    if let Some(relation_id) = self.bind_quarantine_omission(omission) {
                        separately_quarantined.insert(relation_id);
                    }
                }
                _ => {
                    frontier_refs.insert(omission.edge_dependent.clone());
                    partial = true;
                }
            }
        }
        (frontier_refs, separately_quarantined, partial)
    }

    /// Binds one cross-scope omission to the retained quarantine relation ID
    /// for the omitted source/dependent edge.
    fn bind_quarantine_omission(&self, omission: &RevocationOmission) -> Option<String> {
        let source = GrantId::new(omission.edge_source.as_str()).ok()?;
        let dependent = GrantId::new(omission.edge_dependent.as_str()).ok()?;
        self.quarantine_for_edge(&source, &dependent)
            .map(|relation| relation.relation_id.clone())
    }

    /// Computes a package-level revocation-closure verdict for one grant
    /// (#2875 items 6, 7). The durable fencing owner (#2100) consumes a
    /// `Complete` verdict for durable fencing.
    ///
    /// The structural walk follows admitted inheritance (currently same-root)
    /// from the origin, recording the same-root denominator and quarantined
    /// dependents. Legacy cross-root member and transition projections remain
    /// empty because no trusted issuer exists. The bounded engine outcome is
    /// reconciled against that walk: completeness requires its affected set to
    /// match the reached set exactly, with no frontier, quarantine frontier,
    /// or omissions. Every cross-root omission remains partial even when its
    /// local relation ID is retained in `separately_quarantined`; that ID is
    /// not a verified owner receipt. Anything less is an explicit
    /// partial/unknown state with the exact frontier and engine omissions.
    pub fn revocation_closure_verdict(
        &self,
        origin: &GrantId,
        fence: &StateFence,
        bounds: &eliot_influence::RevocationBounds,
    ) -> Result<RevocationClosureVerdict, AuthorityError> {
        let target = self
            .grants
            .get(origin)
            .ok_or_else(|| AuthorityError::MissingParent(origin.clone()))?;
        let authority_root_ref = target.authority_root_ref.clone();
        // Structural walk: the stack discipline of `delegated_closure`
        // (grant-id-ordered children, parent before child). The legacy
        // `crossed`/`authorizing` bookkeeping cannot become nonempty through
        // current construction or recovery, which admit no transitions.
        let mut members = vec![GrantClosureMemberRef {
            grant_id: target.grant_id.clone(),
            parent_grant_id: target.parent_grant_id.clone(),
        }];
        let mut authorized_cross_root = Vec::new();
        let mut traversed = BTreeSet::new();
        let mut unbound: BTreeSet<String> = BTreeSet::new();
        let mut reached: BTreeSet<String> = BTreeSet::from([origin.as_str().to_owned()]);
        let mut seen = BTreeSet::new();
        seen.insert(target.grant_id.clone());
        let mut frontier: Vec<(GrantId, bool, Option<String>)> =
            vec![(target.grant_id.clone(), false, None)];
        while let Some((current, crossed, authorizing)) = frontier.pop() {
            let Some(node) = self.grants.get(&current) else {
                continue;
            };
            let mut children: Vec<&CapabilityGrant> = self
                .grants
                .values()
                .filter(|grant| grant.parent_grant_id.as_ref() == Some(&current))
                .collect();
            children.sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
            for child in children {
                if !seen.insert(child.grant_id.clone()) {
                    continue;
                }
                if !edge_is_authorized(node, child, &self.transitions) {
                    // Unauthorized in-map edge: never followed; the active
                    // dependent stays unresolved and forces partial/unknown.
                    unbound.insert(child.grant_id.as_str().to_owned());
                    continue;
                }
                let edge_crosses =
                    crosses_authority_root(&node.authority_root_ref, &child.authority_root_ref);
                let child_authorizing = if edge_crosses {
                    let Some(receipt) = self.transition_for_edge(&node.grant_id, &child.grant_id)
                    else {
                        unbound.insert(child.grant_id.as_str().to_owned());
                        continue;
                    };
                    traversed.insert(receipt.transition_id.clone());
                    Some(receipt.transition_id.clone())
                } else {
                    authorizing.clone()
                };
                reached.insert(child.grant_id.as_str().to_owned());
                if crossed || edge_crosses {
                    let Some(receipt_id) = child_authorizing.clone() else {
                        unbound.insert(child.grant_id.as_str().to_owned());
                        continue;
                    };
                    authorized_cross_root.push(AuthorizedCrossRootMember {
                        grant_id: child.grant_id.clone(),
                        parent_grant_id: node.grant_id.clone(),
                        authority_root_ref: child.authority_root_ref.clone(),
                        authorizing_transition_id: receipt_id,
                    });
                    frontier.push((child.grant_id.clone(), true, child_authorizing));
                } else {
                    members.push(GrantClosureMemberRef {
                        grant_id: child.grant_id.clone(),
                        parent_grant_id: child.parent_grant_id.clone(),
                    });
                    frontier.push((child.grant_id.clone(), false, None));
                }
            }
        }
        let quarantined_frontier = self.collect_quarantined_frontier(&reached);
        let outcome = self.transitive_revocation_closure(origin, fence, bounds)?;
        let (frontier_refs, separately_quarantined, partial) =
            self.reconcile_engine_outcome(&outcome, &reached, unbound, &quarantined_frontier);
        let state = if partial {
            RevocationClosureState::PartialOrUnknown {
                frontier: frontier_refs.into_iter().collect(),
                omissions: outcome.omissions,
                separately_quarantined: separately_quarantined.into_iter().collect(),
            }
        } else {
            RevocationClosureState::Complete {
                separately_quarantined: separately_quarantined.into_iter().collect(),
            }
        };
        Ok(RevocationClosureVerdict {
            origin: origin.clone(),
            revision: self.revision,
            authority_root_ref,
            members,
            authorized_cross_root,
            quarantined_frontier,
            traversed_transitions: traversed.into_iter().collect(),
            state,
        })
    }

    pub fn snapshot(
        &self,
        snapshot_id: SnapshotId,
        holder: &PrincipalRef,
        work_scope: &WorkScopeBinding,
        session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<EffectiveCapabilitySnapshot, AuthorityError> {
        validate_context(work_scope, session)?;
        let mut paths = Vec::new();
        for grant in self.grants.values().filter(|grant| &grant.holder == holder) {
            if let Ok(path) = self.effective_path(grant, work_scope, session, now) {
                paths.push(path);
            }
        }
        if paths.is_empty() {
            return Err(AuthorityError::NoEffectivePath);
        }
        Ok(EffectiveCapabilitySnapshot {
            snapshot_id,
            holder: holder.clone(),
            work_scope: work_scope.clone(),
            session: session.clone(),
            grant_graph_revision: self.revision,
            paths,
        })
    }

    fn effective_path(
        &self,
        leaf: &CapabilityGrant,
        work_scope: &WorkScopeBinding,
        session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<EffectiveCapabilityPath, AuthorityError> {
        let mut cursor = leaf;
        let mut path = Vec::new();
        let mut effective = leaf.authority.clone();
        loop {
            self.validate_active(cursor, work_scope, session, now)?;
            path.push(cursor.grant_id.clone());
            let Some(parent_id) = &cursor.parent_grant_id else {
                break;
            };
            let parent = self
                .grants
                .get(parent_id)
                .ok_or_else(|| AuthorityError::MissingParent(parent_id.clone()))?;
            // #2875 item 10: the same edge invariant as graph validation.
            // No caller-supplied receipt can authorize a crossing here, so a
            // quarantined relation can never appear in an effective snapshot.
            if !edge_is_authorized(parent, cursor, &self.transitions) {
                return Err(AuthorityError::GrantNotNarrower(cursor.grant_id.clone()));
            }
            effective = effective.intersection(&parent.authority)?;
            cursor = parent;
        }
        path.reverse();
        Ok(EffectiveCapabilityPath {
            grant_path: path,
            authority: effective,
        })
    }

    fn validate_active(
        &self,
        grant: &CapabilityGrant,
        work_scope: &WorkScopeBinding,
        session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<(), AuthorityError> {
        if self.revoked.contains(&grant.grant_id) || grant.status == GrantStatus::Revoked {
            return Err(AuthorityError::GrantRevoked(grant.grant_id.clone()));
        }
        if grant.status != GrantStatus::Active {
            return Err(AuthorityError::GrantInactive(grant.grant_id.clone()));
        }
        if now >= grant.expires_at {
            return Err(AuthorityError::Expired);
        }
        if grant.binding.state_fence != work_scope.state_fence
            || grant.binding.state_fence != session.state_fence
        {
            return Err(AuthorityError::FenceMismatch);
        }
        if !grant
            .binding
            .authority_epoch
            .is_same_authority(&session.authority_epoch)
        {
            return Err(AuthorityError::EpochMismatch);
        }
        Ok(())
    }

    fn validate_cycles(&self) -> Result<(), AuthorityError> {
        for start in self.grants.keys() {
            let mut seen = BTreeSet::new();
            let mut cursor = Some(start);
            while let Some(id) = cursor {
                if !seen.insert(id.clone()) {
                    return Err(AuthorityError::GrantCycle(id.clone()));
                }
                cursor = self
                    .grants
                    .get(id)
                    .and_then(|grant| grant.parent_grant_id.as_ref());
            }
        }
        Ok(())
    }

    /// Validates every delegation edge as same-root narrowing (#2875 items
    /// 1, 2, 10). This module cannot verify owner issuance for root-transition
    /// receipts, so cross-root child edges are rejected.
    ///
    /// Refused with [`AuthorityError::GrantNotNarrower`] naming the child
    /// when it leaves the parent's authority root or is not narrower than its
    /// parent on any of the four narrowing axes: issuer is not the
    /// parent's holder, authority is not a strict subset of the parent's
    /// authority, `expires_at` is later than the parent's, or `max_uses`
    /// exceeds the parent's. A parent naming no grant in this graph is
    /// still [`AuthorityError::MissingParent`]. These clauses are the
    /// fail-closed narrowing boundary of A0.3 "hidden creation or
    /// expansion of authority": a transition authorizes the re-root, never
    /// widening, so a crossing can never expand authority, effect, or
    /// lifetime.
    ///
    /// Cross-root lineage without a receipt never enters this map: recovery
    /// migrates it to an inert [`QuarantinedCrossRootRelation`] with its
    /// full lineage retained, which is A12.5 "Incomplete lineage creates
    /// scoped quarantine or an unknown, not global memory deletion", I12.20
    /// "quarantine the bounded affected scope and open Problem State", and
    /// I15.7 "may be quarantined from agents but retained for forensics"
    /// (#686: "quarantine is not erasure"). The retained relation is
    /// declared with the dedicated cross-scope influence relation by
    /// [`transitive_revocation_closure`](Self::transitive_revocation_closure),
    /// so the bounded evaluator records a typed `OmissionCause::CrossScope`
    /// omission naming the exact edge position, and
    /// [`revocation_closure_verdict`](Self::revocation_closure_verdict)
    /// preserves that omission and dependent in partial/unknown state, with
    /// the retained relation ID as evidence only. Revocation cannot widen
    /// scope or effect.
    fn validate_edges(&self) -> Result<(), AuthorityError> {
        for child in self.grants.values() {
            let Some(parent_id) = &child.parent_grant_id else {
                continue;
            };
            let parent = self
                .grants
                .get(parent_id)
                .ok_or_else(|| AuthorityError::MissingParent(parent_id.clone()))?;
            // Use the same item-10 edge invariant as effective-path
            // construction; narrowing remains an independent check below.
            if !edge_is_authorized(parent, child, &self.transitions) {
                return Err(AuthorityError::GrantNotNarrower(child.grant_id.clone()));
            }
            check_narrowing(parent, child)?;
        }
        Ok(())
    }
}

fn validate_context(
    work_scope: &WorkScopeBinding,
    session: &SessionBinding,
) -> Result<(), AuthorityError> {
    work_scope
        .state_fence
        .validate()
        .map_err(|_| AuthorityError::FenceMismatch)?;
    session
        .state_fence
        .validate()
        .map_err(|_| AuthorityError::FenceMismatch)?;
    if work_scope.state_fence != session.state_fence {
        return Err(AuthorityError::FenceMismatch);
    }
    if !session
        .authority_epoch
        .is_same_authority(&session.state_fence.authority_epoch)
    {
        return Err(AuthorityError::EpochMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntroductionStatus {
    Active,
    Suspended,
    Revoked,
    Stale,
    Consumed,
    Expired,
}

/// Exact resource facet presented for one holder/session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityIntroduction {
    pub introduction_id: IntroductionId,
    pub holder: PrincipalRef,
    pub supporting_grant_refs: BTreeSet<GrantId>,
    pub resource_handle: String,
    pub facet_manifest_ref: String,
    pub introduced_authority: AuthoritySet,
    pub work_scope: WorkScopeBinding,
    pub session: SessionBinding,
    pub grant_graph_revision: u64,
    pub expires_at: LogicalTime,
    pub remaining_calls: u32,
    pub status: IntroductionStatus,
}

impl CapabilityIntroduction {
    #[allow(clippy::too_many_arguments)]
    pub fn compile(
        introduction_id: IntroductionId,
        holder: PrincipalRef,
        supporting_grant_refs: impl IntoIterator<Item = GrantId>,
        resource_handle: impl Into<String>,
        facet_manifest_ref: impl Into<String>,
        introduced_authority: AuthoritySet,
        snapshot: &EffectiveCapabilitySnapshot,
        expires_at: LogicalTime,
        max_calls: u32,
    ) -> Result<Self, AuthorityError> {
        let resource_handle = resource_handle.into();
        let facet_manifest_ref = facet_manifest_ref.into();
        validate_text(&resource_handle, "resource_handle")?;
        validate_text(&facet_manifest_ref, "facet_manifest_ref")?;
        if holder != snapshot.holder || max_calls == 0 {
            return Err(AuthorityError::InvalidField(
                "introduction_holder_or_budget",
            ));
        }
        let supporting_grant_refs = supporting_grant_refs.into_iter().collect::<BTreeSet<_>>();
        if supporting_grant_refs.is_empty()
            || supporting_grant_refs
                .iter()
                .any(|grant| !snapshot.has_supporting_grant(grant))
        {
            return Err(AuthorityError::SupportingPathMissing);
        }
        let path_covers = snapshot.paths.iter().any(|path| {
            supporting_grant_refs
                .iter()
                .all(|grant| path.grant_path.contains(grant))
                && introduced_authority.is_subset_of(&path.authority)
        });
        if !path_covers {
            return Err(AuthorityError::NoEffectivePath);
        }
        Ok(Self {
            introduction_id,
            holder,
            supporting_grant_refs,
            resource_handle,
            facet_manifest_ref,
            introduced_authority,
            work_scope: snapshot.work_scope.clone(),
            session: snapshot.session.clone(),
            grant_graph_revision: snapshot.grant_graph_revision,
            expires_at,
            remaining_calls: max_calls,
            status: IntroductionStatus::Active,
        })
    }

    pub fn authorize_call(
        &mut self,
        operation: &str,
        resource: &str,
        effect: EffectClass,
        snapshot: &EffectiveCapabilitySnapshot,
        now: LogicalTime,
    ) -> Result<(), AuthorityError> {
        if self.status != IntroductionStatus::Active {
            return Err(AuthorityError::Revoked);
        }
        if now >= self.expires_at {
            self.status = IntroductionStatus::Expired;
            return Err(AuthorityError::Expired);
        }
        if self.remaining_calls == 0 {
            self.status = IntroductionStatus::Consumed;
            return Err(AuthorityError::UseBudgetExhausted);
        }
        snapshot.validate_context(&self.work_scope, &self.session)?;
        if snapshot.grant_graph_revision != self.grant_graph_revision
            || self
                .supporting_grant_refs
                .iter()
                .any(|grant| !snapshot.has_supporting_grant(grant))
        {
            self.status = IntroductionStatus::Stale;
            return Err(AuthorityError::GrantRevoked(
                self.supporting_grant_refs
                    .iter()
                    .next()
                    .cloned()
                    .ok_or(AuthorityError::SupportingPathMissing)?,
            ));
        }
        if !self.introduced_authority.operations.contains(operation) {
            return Err(AuthorityError::UnauthorizedOperation);
        }
        if !self.introduced_authority.resources.contains(resource) {
            return Err(AuthorityError::UnauthorizedResource);
        }
        if effect_rank(effect) > effect_rank(self.introduced_authority.max_effect) {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        self.remaining_calls -= 1;
        if self.remaining_calls == 0 {
            self.status = IntroductionStatus::Consumed;
        }
        Ok(())
    }
}

#[cfg(test)]
mod recovery_tests {
    #![allow(clippy::expect_used)] // test-only panic-acceptable (#838).
    use std::error::Error;

    use super::*;
    use eliot_contracts::{
        ContractId, EpochId, EpochLineageId, ResourceGeneration, StateFence, canonical_json_bytes,
    };
    use eliot_receipts::ProofCeiling;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    type TestResult = Result<(), Box<dyn Error>>;

    fn binding() -> Result<AuthorityBinding, Box<dyn Error>> {
        let authority_epoch = test_epoch(TEST_LINEAGE_A, 1);
        let state_fence = StateFence::new(authority_epoch.clone(), ResourceGeneration::new(1)?);
        Ok(AuthorityBinding {
            authority_id: ContractId::new("authority:test")?,
            authority_owner: "G-01".to_owned(),
            authority_epoch,
            state_fence,
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        })
    }

    fn grant(
        id: &str,
        parent: Option<&str>,
        issuer: &str,
        holder: &str,
        authority: AuthoritySet,
    ) -> Result<CapabilityGrant, Box<dyn Error>> {
        Ok(CapabilityGrant {
            grant_id: GrantId::new(id)?,
            parent_grant_id: parent.map(GrantId::new).transpose()?,
            authority_root_ref: "root:test".to_owned(),
            issuer: PrincipalRef::new(issuer)?,
            holder: PrincipalRef::new(holder)?,
            authority,
            inherited_source_ceiling: None,
            binding: binding()?,
            issued_at: LogicalTime::new(1),
            expires_at: LogicalTime::new(10),
            max_uses: 2,
            status: GrantStatus::Active,
        })
    }

    fn graph() -> Result<GrantGraph, Box<dyn Error>> {
        let root = grant(
            "grant:root",
            None,
            "principal:root",
            "principal:child",
            AuthoritySet::new(
                ["read".to_owned(), "write".to_owned()],
                ["resource:a".to_owned(), "resource:b".to_owned()],
                EffectClass::ExternalEffect,
            )?,
        )?;
        let child = grant(
            "grant:child",
            Some("grant:root"),
            "principal:child",
            "principal:leaf",
            AuthoritySet::new(
                ["read".to_owned()],
                ["resource:a".to_owned()],
                EffectClass::Read,
            )?,
        )?;
        Ok(GrantGraph::from_grants([root, child], 7)?)
    }

    #[test]
    fn recovery_roundtrip_preserves_complete_graph_and_revision() -> TestResult {
        let graph = graph()?;
        let snapshot = graph.recovery_snapshot()?;
        let restored = GrantGraph::from_recovery_snapshot(&snapshot)?;
        assert_eq!(restored.revision(), 7);
        assert_eq!(restored.recovery_snapshot()?, snapshot);
        Ok(())
    }

    #[test]
    fn recovery_preserves_revocations_without_replaying_revoke() -> TestResult {
        let mut graph = graph()?;
        graph.revoke(&GrantId::new("grant:child")?)?;
        let snapshot = graph.recovery_snapshot()?;
        assert_eq!(snapshot.revision, 8);
        assert_eq!(snapshot.revoked, ["grant:child"]);
        let restored = GrantGraph::from_recovery_snapshot(&snapshot)?;
        assert_eq!(restored.revision(), 8);
        assert_eq!(restored.recovery_snapshot()?, snapshot);
        Ok(())
    }

    #[test]
    fn recovery_rejects_zero_revision_unknown_duplicate_cycle_and_widening() -> TestResult {
        let base = graph()?.recovery_snapshot()?;

        let mut zero_revision = base.clone();
        zero_revision.revision = 0;
        assert!(matches!(
            GrantGraph::from_recovery_snapshot(&zero_revision),
            Err(AuthorityError::InvalidField("grant_graph_revision"))
        ));

        let mut unknown_revocation = base.clone();
        unknown_revocation.revoked.push("grant:unknown".to_owned());
        unknown_revocation.revoked.sort();
        assert!(matches!(
            GrantGraph::from_recovery_snapshot(&unknown_revocation),
            Err(AuthorityError::MissingParent(id)) if id.as_str() == "grant:unknown"
        ));

        let mut duplicate = base.clone();
        duplicate.grants.push(duplicate.grants[1].clone());
        assert!(matches!(
            GrantGraph::from_recovery_snapshot(&duplicate),
            Err(AuthorityError::InvalidField("grant_graph_recovery.grants"))
        ));

        let mut cycle = base.clone();
        cycle.grants[0].parent_grant_id = Some("grant:child".to_owned());
        assert!(matches!(
            GrantGraph::from_recovery_snapshot(&cycle),
            Err(AuthorityError::GrantCycle(_))
        ));

        let mut widened = base;
        widened.grants[0].allowed_operations = vec!["read".to_owned(), "write".to_owned()];
        widened.grants[0].allowed_resources =
            vec!["resource:a".to_owned(), "resource:b".to_owned()];
        widened.grants[0].max_effect = EffectClass::ExternalEffect;
        let widened_error = GrantGraph::from_recovery_snapshot(&widened)
            .err()
            .ok_or("widened child was accepted")?;
        assert_eq!(
            widened_error,
            AuthorityError::GrantNotNarrower(GrantId::new("grant:child")?)
        );
        Ok(())
    }

    #[test]
    fn recovery_validate_is_semantic_and_empty_genesis_is_explicit() -> TestResult {
        let empty = GrantGraph::from_grants(std::iter::empty(), 1)?;
        let empty_snapshot = empty.recovery_snapshot()?;
        empty_snapshot.validate()?;
        assert_eq!(
            GrantGraph::from_recovery_snapshot(&empty_snapshot)?.recovery_snapshot()?,
            empty_snapshot
        );

        let mut zero = empty_snapshot;
        zero.revision = 0;
        assert!(matches!(
            zero.validate(),
            Err(AuthorityError::InvalidField("grant_graph_revision"))
        ));

        let mut missing_parent = graph()?.recovery_snapshot()?;
        missing_parent.grants[1].parent_grant_id = Some("grant:missing".to_owned());
        assert!(matches!(
            missing_parent.validate(),
            Err(AuthorityError::MissingParent(id)) if id.as_str() == "grant:missing"
        ));
        Ok(())
    }

    #[test]
    fn recovery_json_roundtrip_and_unknown_fields_are_rejected() -> TestResult {
        let snapshot = graph()?.recovery_snapshot()?;
        let encoded = serde_json::to_string(&snapshot)?;
        let decoded: GrantGraphRecoverySnapshot = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, snapshot);

        let mut unknown_top_level = serde_json::to_value(&snapshot)?;
        unknown_top_level
            .as_object_mut()
            .ok_or("snapshot was not a JSON object")?
            .insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(serde_json::from_value::<GrantGraphRecoverySnapshot>(unknown_top_level).is_err());

        let mut unknown_record = serde_json::to_value(&snapshot)?;
        let records = unknown_record
            .get_mut("grants")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("grants was not a JSON array")?;
        records
            .first_mut()
            .ok_or("expected a grant record")?
            .as_object_mut()
            .ok_or("grant record was not a JSON object")?
            .insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(serde_json::from_value::<GrantGraphRecoverySnapshot>(unknown_record).is_err());
        Ok(())
    }

    #[test]
    fn recovery_order_and_canonical_bytes_are_insertion_independent() -> TestResult {
        let first = {
            let root = grant(
                "grant:root",
                None,
                "principal:root",
                "principal:child",
                AuthoritySet::new(
                    ["read".to_owned(), "write".to_owned()],
                    ["resource:a".to_owned(), "resource:b".to_owned()],
                    EffectClass::ExternalEffect,
                )?,
            )?;
            let child = grant(
                "grant:child",
                Some("grant:root"),
                "principal:child",
                "principal:leaf",
                AuthoritySet::new(
                    ["read".to_owned()],
                    ["resource:a".to_owned()],
                    EffectClass::Read,
                )?,
            )?;
            GrantGraph::from_grants([root, child], 7)?.recovery_snapshot()?
        };
        let second = {
            let root = grant(
                "grant:root",
                None,
                "principal:root",
                "principal:child",
                AuthoritySet::new(
                    ["write".to_owned(), "read".to_owned()],
                    ["resource:b".to_owned(), "resource:a".to_owned()],
                    EffectClass::ExternalEffect,
                )?,
            )?;
            let child = grant(
                "grant:child",
                Some("grant:root"),
                "principal:child",
                "principal:leaf",
                AuthoritySet::new(
                    ["read".to_owned()],
                    ["resource:a".to_owned()],
                    EffectClass::Read,
                )?,
            )?;
            GrantGraph::from_grants([child, root], 7)?.recovery_snapshot()?
        };
        assert_eq!(first, second);
        assert_eq!(
            canonical_json_bytes(&first)?,
            canonical_json_bytes(&second)?
        );

        let mut reordered = first.clone();
        reordered.grants.reverse();
        assert!(matches!(
            reordered.validate(),
            Err(AuthorityError::InvalidField("grant_graph_recovery.grants"))
        ));

        let mut revoked = graph()?;
        revoked.revoke(&GrantId::new("grant:root")?)?;
        revoked.revoke(&GrantId::new("grant:child")?)?;
        let mut revoked_snapshot = revoked.recovery_snapshot()?;
        revoked_snapshot.revoked.reverse();
        assert!(matches!(
            revoked_snapshot.validate(),
            Err(AuthorityError::InvalidField("grant_graph_recovery.revoked"))
        ));
        Ok(())
    }
}
