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
/// declaration, recovery partition, and transition admission — calls this
/// function, so comments, traversal, and authority use cannot maintain
/// different meanings of a root crossing. A normal delegation edge either
/// stays inside one root or names an exact admitted [`RootTransitionReceipt`]
/// authorizing the re-root; a child can never choose a new root merely by
/// setting a string while borrowing the parent's holder and authority.
fn crosses_authority_root(from_root: &str, to_root: &str) -> bool {
    from_root != to_root
}

/// Item-10 edge invariant: one delegation edge is authorized authority
/// inheritance exactly when it stays inside one root or names an exact
/// admitted [`RootTransitionReceipt`] for this parent/child pair. Shared by
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

/// Deterministic relation receipt for one quarantined cross-root edge, so
/// legacy migration replays exactly: the same snapshot always restores the
/// same relation identity.
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

/// Owner-issued root-transition (bridge) receipt (#2875 item 4).
///
/// The canonical root-transition contract: the only way a normal
/// [`CapabilityGrant`] parent edge may leave its authority root. The receipt
/// is admitted as a separate explicit input at graph construction
/// ([`GrantGraph::from_grants_with_transitions`]) or carried in the recovery
/// snapshot's `root_transitions` section, is validated against the live
/// graph (exact parent/child identities and edge, exact from/to roots,
/// issuer equals the parent's holder, fence/epoch bound to the child, and
/// an issuance revision at or before the restored revision), and is then
/// stored as graph state. Every consumer — effective-path construction,
/// revocation edge declaration, closure verdicts, recovery re-emission, and
/// durable fencing — reads the stored receipt; equality to caller-supplied
/// fields is not authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootTransitionReceipt {
    /// Owner-issued transition identity, unique per graph.
    pub transition_id: String,
    /// Delegating parent grant; the crossing source.
    pub parent_grant_id: String,
    /// Re-rooted child grant; the crossing dependent.
    pub child_grant_id: String,
    /// Exact parent root the edge leaves.
    pub from_authority_root_ref: String,
    /// Exact child root the edge enters.
    pub to_authority_root_ref: String,
    /// Owner principal authorizing the re-root; must equal the parent's
    /// holder, so a child cannot self-authorize a new root.
    pub issuer: String,
    /// Fence/epoch binding of the crossing, bound to the child grant.
    pub binding: AuthorityBinding,
    /// Graph revision this receipt was issued against. Admission requires
    /// a nonzero revision at or before the restored revision: receipts
    /// persist across revokes, and every restore re-validates the exact
    /// edge, roots, issuer, and fence binding.
    pub admitted_at_revision: u64,
}

/// Admits one root-transition receipt against a complete grant map, shared
/// by graph construction and recovery restore. Changed roots, edges,
/// issuers, or bindings under one receipt fail closed; a reused transition
/// identity or a second receipt for one edge is an identity conflict.
fn admit_transition_receipt(
    grants: &BTreeMap<GrantId, CapabilityGrant>,
    receipt: &RootTransitionReceipt,
    revision: u64,
    transitions: &mut BTreeMap<(GrantId, GrantId), RootTransitionReceipt>,
) -> Result<(), AuthorityError> {
    validate_text(
        &receipt.transition_id,
        "root_transition_receipt.transition_id",
    )?;
    validate_text(
        &receipt.from_authority_root_ref,
        "root_transition_receipt.from_authority_root_ref",
    )?;
    validate_text(
        &receipt.to_authority_root_ref,
        "root_transition_receipt.to_authority_root_ref",
    )?;
    validate_text(&receipt.issuer, "root_transition_receipt.issuer")?;
    if !crosses_authority_root(
        &receipt.from_authority_root_ref,
        &receipt.to_authority_root_ref,
    ) {
        return Err(AuthorityError::InvalidField(
            "root_transition_receipt.roots",
        ));
    }
    if receipt.admitted_at_revision == 0 || receipt.admitted_at_revision > revision {
        return Err(AuthorityError::InvalidField(
            "root_transition_receipt.revision",
        ));
    }
    receipt
        .binding
        .state_fence
        .validate()
        .map_err(|_| AuthorityError::FenceMismatch)?;
    if !receipt
        .binding
        .authority_epoch
        .is_same_authority(&receipt.binding.state_fence.authority_epoch)
    {
        return Err(AuthorityError::EpochMismatch);
    }
    let parent_id = GrantId::new(receipt.parent_grant_id.clone())?;
    let child_id = GrantId::new(receipt.child_grant_id.clone())?;
    let parent = grants.get(&parent_id).ok_or(AuthorityError::InvalidField(
        "root_transition_receipt.parent",
    ))?;
    let child = grants.get(&child_id).ok_or(AuthorityError::InvalidField(
        "root_transition_receipt.child",
    ))?;
    if child.parent_grant_id.as_ref() != Some(&parent_id) {
        return Err(AuthorityError::InvalidField("root_transition_receipt.edge"));
    }
    if parent.authority_root_ref != receipt.from_authority_root_ref
        || child.authority_root_ref != receipt.to_authority_root_ref
    {
        return Err(AuthorityError::InvalidField(
            "root_transition_receipt.roots",
        ));
    }
    if parent.holder.as_str() != receipt.issuer.as_str() {
        return Err(AuthorityError::InvalidField(
            "root_transition_receipt.issuer",
        ));
    }
    if receipt.binding.state_fence != child.binding.state_fence {
        return Err(AuthorityError::FenceMismatch);
    }
    if !receipt
        .binding
        .authority_epoch
        .is_same_authority(&child.binding.authority_epoch)
    {
        return Err(AuthorityError::EpochMismatch);
    }
    if transitions
        .values()
        .any(|known| known.transition_id == receipt.transition_id)
    {
        return Err(AuthorityError::IdentityConflict);
    }
    if transitions
        .insert((parent_id, child_id), receipt.clone())
        .is_some()
    {
        return Err(AuthorityError::IdentityConflict);
    }
    Ok(())
}

pub const GRANT_GRAPH_RECOVERY_SCHEMA: &str = "eliot.authority.grant-graph-recovery";
pub const GRANT_GRAPH_RECOVERY_VERSION: u16 = 1;

/// Complete durable state of a grant graph, in deterministic wire form.
///
/// `grants` carries admitted authority lineage only: a cross-root edge
/// without an exact admitted [`RootTransitionReceipt`] never restores into
/// the authority map. Pre-fix snapshots predate the two trailing sections
/// and restore with empty ones; their cross-root active edges migrate to
/// quarantined relations instead of being silently adopted or reactivated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantGraphRecoverySnapshot {
    pub schema: String,
    pub version: u16,
    pub revision: u64,
    pub grants: Vec<GrantRecoveryRecord>,
    pub revoked: Vec<String>,
    /// Admitted root-transition receipts in transition-id order (#2875).
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
        for receipt in &self.root_transitions {
            validate_text(
                &receipt.transition_id,
                "root_transition_receipt.transition_id",
            )?;
            if let Some(previous) = previous
                && previous >= receipt.transition_id.as_str()
            {
                return Err(AuthorityError::InvalidField(
                    "grant_graph_recovery.root_transitions",
                ));
            }
            previous = Some(receipt.transition_id.as_str());
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

    /// Restores owned graph state: admitted authority, admitted transition
    /// receipts, and inert quarantined relations (#2875 item 9).
    ///
    /// Grants whose parent edge stays inside one root — or names an exact
    /// admitted transition receipt — restore into the authority map.
    /// Grants whose parent edge crosses roots without a receipt migrate to
    /// inert [`QuarantinedCrossRootRelation`] records with their full
    /// lineage retained, as do their transitive descendants; migration is
    /// deterministic, so exact replay restores the exact same graph. A
    /// cross-root edge that is not even a narrowing is not lineage and is
    /// refused with [`AuthorityError::GrantNotNarrower`]. Explicit
    /// quarantined records restore as quarantined evidence only: a record
    /// that is not cross-root, disagrees with its parent's root, or names
    /// an admitted grant fails closed instead of being silently
    /// reinterpreted. A legacy cross-root child therefore can never restore
    /// as active authority.
    fn restore_owned(snapshot: &GrantGraphRecoverySnapshot) -> Result<GrantGraph, AuthorityError> {
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
        let mut transitions = BTreeMap::new();
        for receipt in &snapshot.root_transitions {
            admit_transition_receipt(&full_map, receipt, snapshot.revision, &mut transitions)?;
        }
        let probe = GrantGraph {
            grants: full_map,
            revoked: BTreeSet::new(),
            revision: snapshot.revision,
            transitions,
            quarantined: BTreeMap::new(),
        };
        probe.validate_cycles()?;
        let mut graph = probe.partition_restored()?;
        let mut explicit: BTreeMap<GrantId, CapabilityGrant> = BTreeMap::new();
        for record in &snapshot.quarantined_cross_root {
            let child = grant_from_recovery_record(&record.child)?;
            child.validate_local()?;
            if explicit.insert(child.grant_id.clone(), child).is_some() {
                return Err(AuthorityError::IdentityConflict);
            }
        }
        for record in &snapshot.quarantined_cross_root {
            graph.restore_quarantine_record(record, &explicit)?;
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
/// cross-products between independent alternate paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveCapabilitySnapshot {
    pub snapshot_id: SnapshotId,
    pub holder: PrincipalRef,
    pub work_scope: WorkScopeBinding,
    pub session: SessionBinding,
    pub grant_graph_revision: u64,
    pub paths: Vec<EffectiveCapabilityPath>,
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

/// One receipt-authorized cross-root descendant in a closure verdict.
///
/// The member's authority derives through an admitted root crossing, so it
/// is enumerated separately from the same-root denominator: the durable
/// fencing owner (#2100) either fences the identity on its own root or
/// refuses, and the exact authorizing receipt travels with the member.
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
/// The dependent authorizes nothing, but the traversal refused to follow
/// it, so the verdict binds the exact separate-quarantine receipt: #2100
/// consumes the receipt instead of fencing an inert identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedFrontierMember {
    /// Quarantined dependent identity.
    pub grant_id: GrantId,
    /// Crossing source identity.
    pub parent_grant_id: GrantId,
    /// Exact separate-quarantine receipt for this edge.
    pub relation_id: String,
}

/// Honest revocation-closure state (#2875 item 6).
///
/// A traversal that encounters an active/unresolved cross-root dependent
/// never reports a clear complete closure merely because it emitted an
/// omission: completeness requires every encountered dependent in the
/// affected set or bound to a verified separate-quarantine receipt, and
/// anything less is an explicit partial/unknown state with the exact
/// frontier and omissions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationClosureState {
    /// Every encountered dependent is in the affected denominator, and
    /// every omitted cross-root dependent is bound to a verified
    /// separate-quarantine receipt.
    Complete { separately_quarantined: Vec<String> },
    /// Recovery-required: the exact unresolved frontier plus the exact
    /// engine omissions in engine order. Bound separate-quarantine
    /// receipts travel alongside so partial progress stays auditable.
    PartialOrUnknown {
        frontier: Vec<String>,
        omissions: Vec<RevocationOmission>,
        separately_quarantined: Vec<String>,
    },
}

/// Typed revocation-closure verdict: a complete denominator or an explicit
/// partial/unknown state, never an omission-labelled success.
///
/// The exact verdict the durable descendant-closure fencing owner (#2100)
/// consumes: the same-root denominator, the receipt-authorized cross-root
/// descendants with their authorizing receipts, the quarantined frontier
/// with its separate-quarantine receipts, every traversed transition
/// receipt, and the honest completeness state reconciling the bounded
/// engine outcome against the live graph.
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
    /// Receipt-authorized cross-root descendants in parent-before-child
    /// order; every member's authority derives through a crossing.
    pub authorized_cross_root: Vec<AuthorizedCrossRootMember>,
    /// Quarantined dependents encountered with bound receipts.
    pub quarantined_frontier: Vec<QuarantinedFrontierMember>,
    /// Every transition receipt authorizing a followed crossing, sorted.
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
    /// Constructs a graph of ordinary same-root delegation (#2875 item 2).
    ///
    /// A child whose `authority_root_ref` differs from its parent's is
    /// rejected with [`AuthorityError::GrantNotNarrower`] before entering
    /// the graph; ordinary delegation stays inside one root. A separately
    /// authorized crossing requires
    /// [`from_grants_with_transitions`](Self::from_grants_with_transitions)
    /// with the exact owner-issued receipt.
    pub fn from_grants(
        grants: impl IntoIterator<Item = CapabilityGrant>,
        revision: u64,
    ) -> Result<Self, AuthorityError> {
        Self::from_grants_with_transitions(grants, Vec::new(), revision)
    }

    /// Constructs a graph with explicitly admitted root crossings (#2875
    /// item 4). Every transition receipt is validated against the live
    /// grants: exact parent/child edge, exact from/to roots, issuer equal
    /// to the parent's holder, fence/epoch bound to the child. A cross-root
    /// edge without its exact receipt is rejected; narrowing still applies
    /// to every edge, so a transition authorizes the re-root, never
    /// widening.
    pub fn from_grants_with_transitions(
        grants: impl IntoIterator<Item = CapabilityGrant>,
        transitions: impl IntoIterator<Item = RootTransitionReceipt>,
        revision: u64,
    ) -> Result<Self, AuthorityError> {
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
        let mut admitted = BTreeMap::new();
        for receipt in transitions {
            admit_transition_receipt(&by_id, &receipt, revision, &mut admitted)?;
        }
        let graph = Self {
            grants: by_id,
            revoked: BTreeSet::new(),
            revision,
            transitions: admitted,
            quarantined: BTreeMap::new(),
        };
        graph.validate_cycles()?;
        graph.validate_edges()?;
        Ok(graph)
    }

    /// Exact admitted transition receipt for one delegation edge, if the
    /// owner admitted a root crossing on exactly this parent/child pair.
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
    /// admitted transition receipts, and inert quarantined relations. A
    /// quarantined relation re-emits into the quarantine section only, so
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
    /// used to restore unrecheckable, and now refuses. Nothing that restored
    /// before stops restoring, and no field is newly ignored.
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
        // graph: it follows same-root and receipt-authorized parent links,
        // binds every omitted cross-root dependent to its verified
        // separate-quarantine receipt, and reports anything less as
        // partial/unknown — so a partial verdict, or a closure that
        // under-claims its transitive descendants, still refuses. An
        // omitted dependent without a bound receipt is never silently
        // cleared. Affected references naming no grant in this graph belong
        // to another graph's denominator and refuse nothing.
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
    /// 3. every in-graph grant the verdict can reach - a same-root member or a
    ///    receipt-authorized cross-root member - must already be suppressed,
    ///    otherwise the committed closure under-claims its transitive
    ///    descendants and the stored target set drifted.
    ///
    /// The recheck reads the verdict owner, not the bounded engine directly:
    /// [`GrantGraph::revocation_closure_verdict`] reconciles the engine outcome
    /// against the live graph, follows same-root and receipt-authorized parent
    /// links, binds every omitted cross-root dependent to its verified
    /// separate-quarantine receipt, and reports anything less as
    /// [`RevocationClosureState::PartialOrUnknown`] - so a partial verdict, or a
    /// closure that under-claims its descendants, still refuses, and an omitted
    /// dependent without a bound receipt is never silently cleared.
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
            // whole inside the declared bounds, or an omitted cross-root
            // dependent carried no verified separate-quarantine receipt.
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
    /// Receipt-authorized cross-root descendants and quarantined dependents
    /// are enumerated separately by
    /// [`revocation_closure_verdict`](Self::revocation_closure_verdict),
    /// which carries the exact authorizing and separate-quarantine receipts
    /// the durable fencing owner (#2100) consumes.
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
    /// grant-id order: exact replay restores the exact same partition.
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
                    quarantined_ids.insert(id.clone());
                    self.quarantined
                        .insert(relation.relation_id.clone(), relation);
                    progressed = true;
                } else if admitted.contains_key(parent_id) {
                    if edge_is_authorized(parent, grant, &self.transitions) {
                        admitted.insert(id.clone(), grant.clone());
                    } else {
                        let relation = migrate_to_quarantine(parent, grant, self.revision)?;
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
        // Drop receipts orphaned by quarantine: a receipt whose parent or
        // child no longer names an admitted grant is never consulted (all
        // lookups key on in-map pairs), and retaining it would break
        // re-emission round-trip (restore_owned re-admits receipts against
        // the grants section only).
        self.transitions.retain(|(parent, child), _| {
            admitted.contains_key(parent) && admitted.contains_key(child)
        });
        self.grants = admitted;
        Ok(self)
    }

    /// Restores one explicit quarantined record as inert evidence only. The
    /// record must name a real cross-root edge against its exact parent
    /// root, still narrow its parent, and name no admitted grant: anything
    /// else fails closed instead of being silently reinterpreted. Parents
    /// resolve in the admitted map, migrated quarantine, or the explicit
    /// section itself, so section order never affects the verdict.
    fn restore_quarantine_record(
        &mut self,
        record: &QuarantinedCrossRootRecord,
        explicit: &BTreeMap<GrantId, CapabilityGrant>,
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
        let parent: &CapabilityGrant = match self.grants.get(&parent_id) {
            Some(parent) => parent,
            None => self
                .quarantined
                .values()
                .find(|known| known.child.grant_id == parent_id)
                .map(|known| &known.child)
                .or_else(|| explicit.get(&parent_id))
                .ok_or_else(|| AuthorityError::MissingParent(parent_id.clone()))?,
        };
        if parent.authority_root_ref != record.parent_authority_root_ref {
            return Err(AuthorityError::InvalidField("quarantined_cross_root.root"));
        }
        if !crosses_authority_root(&parent.authority_root_ref, &child.authority_root_ref) {
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
    /// Every authorized delegation edge — same-root, or cross-root with an
    /// exact admitted [`RootTransitionReceipt`] — becomes one qualified
    /// influence edge with
    /// [`PermittedCurrent`](InfluenceEdgeDisposition::PermittedCurrent)
    /// disposition: authorized live-graph edges are current by
    /// construction, so a receipt-authorized cross-root dependent enters
    /// the affected set exactly like a same-root one. An edge that is not
    /// authorized inheritance — and every retained
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
    /// which binds every omitted dependent to its separate-quarantine
    /// receipt or reports an explicit partial/unknown state.
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
        // erasure, and the verdict binds every such omission to its
        // separate-quarantine receipt.
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

    /// Collects the quarantined dependents whose edge source the walk
    /// reached: the separate-quarantine frontier the fencing owner (#2100)
    /// consumes with the verdict.
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
    /// exactly, and every omitted cross-root dependent must bind to its
    /// verified separate-quarantine receipt. Returns the frontier refs, the
    /// bound separate-quarantine receipts, and whether the verdict is
    /// partial/unknown.
    fn reconcile_engine_outcome(
        &self,
        outcome: &eliot_influence::BoundedRevocationOutcome,
        reached: &BTreeSet<String>,
        unbound: BTreeSet<String>,
    ) -> (BTreeSet<String>, BTreeSet<String>, bool) {
        let mut frontier_refs: BTreeSet<String> = outcome.frontier.iter().cloned().collect();
        let mut separately_quarantined: BTreeSet<String> = BTreeSet::new();
        let mut partial = !outcome.complete || !outcome.frontier.is_empty() || !unbound.is_empty();
        frontier_refs.extend(unbound);
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
                    if let Some(relation_id) = self.bind_quarantine_omission(omission) {
                        separately_quarantined.insert(relation_id);
                    } else {
                        frontier_refs.insert(omission.edge_dependent.clone());
                        partial = true;
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

    /// Binds one cross-scope omission to its separate-quarantine receipt:
    /// the exact relation retained for the omitted source/dependent edge.
    fn bind_quarantine_omission(&self, omission: &RevocationOmission) -> Option<String> {
        let source = GrantId::new(omission.edge_source.as_str()).ok()?;
        let dependent = GrantId::new(omission.edge_dependent.as_str()).ok()?;
        self.quarantine_for_edge(&source, &dependent)
            .map(|relation| relation.relation_id.clone())
    }

    /// Computes the honest revocation-closure verdict for one grant (#2875
    /// items 6, 7): the exact denominator the durable fencing owner (#2100)
    /// consumes.
    ///
    /// The structural walk follows authorized inheritance — same-root and
    /// receipt-covered edges — from the origin, recording the same-root
    /// denominator, the receipt-authorized cross-root descendants with
    /// their authorizing receipts, every traversed transition, and the
    /// quarantined dependents encountered with their separate-quarantine
    /// receipts. The bounded engine outcome is then reconciled against
    /// that walk: completeness requires the engine's affected set to match
    /// the reached set exactly and every omitted cross-root dependent to
    /// bind to its verified separate-quarantine receipt. Anything less —
    /// an unfinished traversal, a nonempty frontier, an unbound omission,
    /// or a denominator mismatch — is an explicit partial/unknown state
    /// with the exact frontier and omissions, never an omission-labelled
    /// success.
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
        // (grant-id-ordered children, parent before child), extended
        // across receipt-authorized crossings. `crossed` marks members
        // reached through at least one crossing; `authorizing` carries the
        // nearest crossing receipt above the entry.
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
            self.reconcile_engine_outcome(&outcome, &reached, unbound);
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
            // #2875 item 10: the same edge invariant as graph validation —
            // a path step that leaves the authority root without the exact
            // admitted transition receipt is not an effective path, so a
            // quarantined relation can never appear in a snapshot.
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

    /// Validates every delegation edge as same-root narrowing, unless an
    /// exact admitted root-transition receipt authorizes the crossing
    /// (#2875 items 1, 2, 10).
    ///
    /// Refused with [`AuthorityError::GrantNotNarrower`] naming the child
    /// when the child leaves the parent's authority root without the exact
    /// admitted [`RootTransitionReceipt`] for this parent/child pair (the
    /// restored root clause: a child cannot choose a new root merely by
    /// setting a string), or when the child is not narrower than its
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
    /// binds that omission to the separate-quarantine receipt. Revocation
    /// cannot widen scope or effect.
    fn validate_edges(&self) -> Result<(), AuthorityError> {
        for child in self.grants.values() {
            let Some(parent_id) = &child.parent_grant_id else {
                continue;
            };
            let parent = self
                .grants
                .get(parent_id)
                .ok_or_else(|| AuthorityError::MissingParent(parent_id.clone()))?;
            // Restored root clause (#2875 item 2): ordinary delegation
            // stays inside one root; only the exact admitted transition
            // receipt for this edge authorizes a crossing.
            if crosses_authority_root(&parent.authority_root_ref, &child.authority_root_ref)
                && self
                    .transition_for_edge(&parent.grant_id, &child.grant_id)
                    .is_none()
            {
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
