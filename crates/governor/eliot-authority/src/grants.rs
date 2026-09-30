use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::{
    ClockReading, EpochId, ReceiptId, StateFence, TaskId, canonical_json_bytes, sha256_hex,
};
use eliot_influence::{
    BoundedRevocationRequest, ClosureCompleteness, InfluenceEdgeDisposition, OmissionCause,
    QualifiedInfluenceEdge, RevocationOmission,
};
use eliot_receipts::{
    AuthorityBinding, EffectClass, ReceiptIdentity, SessionBinding, WorkScopeBinding,
};
use eliot_security_contracts::{EffectCeiling, RevocationReason};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::quarantine_evidence::{QuarantineDisposition, VerifiedQuarantineBinding};
use crate::revocation_history::{
    AdmittedRevocationClosure, AuthorityRootRef, ClosureIdentityConflict, OriginTargetMismatch,
    RevocationEvidenceDisposition, RevocationOrigin, ValidatedRevocationClosure,
    derive_suppressions,
};
use crate::root_transition::{
    AdmittedRootTransition, AdmittedRootTransitionRecord, RootTransitionDisposition,
};
use crate::leases::{ActionLease, LeaseId};
use crate::{
    AuthorityError, GrantRestoreOutcome, RevocationHistoryError, validate_digest, validate_text,
};

const REVOCATION_PAGE_EDGE_LIMIT: u64 = 256;
const REVOCATION_PAGE_WORK_LIMIT: u64 = 513;

fn map_bounded_revocation_error(error: eliot_influence::InfluenceError) -> AuthorityError {
    AuthorityError::BoundedRevocation(error)
}

/// Every reference one closure completeness state leaves unresolved: the
/// explicit frontier plus each engine omission's withheld dependent.
///
/// This is the recomputed half of the committed-evidence omission
/// comparison. A complete state resolves nothing, so it reports the empty set
/// and a closure that declares an omission is refusing against a denominator
/// that resolved none.
fn unresolved_references(state: &RevocationClosureState) -> BTreeSet<String> {
    match state {
        RevocationClosureState::Complete { .. } => BTreeSet::new(),
        RevocationClosureState::PartialOrUnknown {
            frontier,
            omissions,
            ..
        } => frontier
            .iter()
            .cloned()
            .chain(
                omissions
                    .iter()
                    .map(|omission| omission.edge_dependent.clone()),
            )
            .collect(),
    }
}

/// Maps one graph-owner refusal onto the typed recovery vocabulary.
///
/// The bounded cause is preserved verbatim so a caller can still tell
/// unsupported schema, incomplete coverage, target drift, and unverified
/// recovery apart. Every other authority refusal means the graph could not
/// answer the question at all, which is unknown history; the mapping is
/// exhaustive so a new authority cause can never be collapsed into a
/// recovery cause by accident.
fn map_bounded_history_error(error: AuthorityError) -> RevocationHistoryError {
    match error {
        AuthorityError::BoundedRevocation(error) => {
            RevocationHistoryError::BoundedRevocation(error)
        }
        AuthorityError::InvalidField(_)
        | AuthorityError::DuplicateGrant(_)
        | AuthorityError::MissingParent(_)
        | AuthorityError::GrantCycle(_)
        | AuthorityError::GrantNotNarrower(_)
        | AuthorityError::GrantInactive(_)
        | AuthorityError::GrantRevoked(_)
        | AuthorityError::NoEffectivePath
        | AuthorityError::SupportingPathMissing
        | AuthorityError::FenceMismatch
        | AuthorityError::EpochMismatch
        | AuthorityError::Expired
        | AuthorityError::Revoked
        | AuthorityError::Consumed
        | AuthorityError::UseBudgetExhausted
        | AuthorityError::UnauthorizedOperation
        | AuthorityError::UnauthorizedResource
        | AuthorityError::UnauthorizedDataClass
        | AuthorityError::EffectCeilingExceeded
        | AuthorityError::IdentityConflict
        | AuthorityError::StaleTransitionEvidence(_)
        | AuthorityError::UnreconciledTransitionEvidence(_)
        | AuthorityError::StaleQuarantineEvidence(_)
        | AuthorityError::StaleEffectAuthority(_)
        | AuthorityError::InvalidLifecycleTransition
        | AuthorityError::ReceiptMismatch
        | AuthorityError::P07Unavailable => RevocationHistoryError::UnknownHistory,
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

pub(crate) fn source_effect_rank(ceiling: EffectCeiling) -> u8 {
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
/// stays inside one root or names exact admitted
/// [`AdmittedRootTransition`] evidence for this parent/child pair; a child can
/// never choose a new root merely by setting a string while borrowing the
/// parent's holder and authority.
fn crosses_authority_root(from_root: &str, to_root: &str) -> bool {
    from_root != to_root
}

/// Item-10 edge invariant: one delegation edge is authorized authority
/// inheritance exactly when it stays inside one root or names exact admitted
/// [`AdmittedRootTransition`] evidence for this parent/child pair. Shared by
/// [`GrantGraph::validate_edges`], effective-path construction, revocation
/// edge declaration, the closure verdict walk, and the recovery partition.
///
/// Map membership IS the authority check, and that is sound only because the
/// map holds admitted evidence exclusively: a member entered
/// `GrantGraph::transitions` only through
/// [`AdmittedRootTransition::admit`] or CURRENT-receipt
/// [`AdmittedRootTransition::admit_restored`], which read CURRENT owner
/// state. Snapshot-local restore admits nothing. A decoded structural
/// record never reaches
/// this map, so this predicate can no longer be satisfied by caller material.
fn edge_is_authorized(
    parent: &CapabilityGrant,
    child: &CapabilityGrant,
    transitions: &BTreeMap<(GrantId, GrantId), AdmittedRootTransition>,
) -> bool {
    !crosses_authority_root(&parent.authority_root_ref, &child.authority_root_ref)
        || transitions.contains_key(&(parent.grant_id.clone(), child.grant_id.clone()))
}

/// The four narrowing clauses: issuer is the parent's holder, authority is
/// a strict subset, `expires_at` is not later, `max_uses` is not larger.
/// Shared by edge validation, legacy-cross-root migration, and quarantined
/// record restore, so a crossing — authorized or quarantined — can never
/// widen authority, effect, or lifetime.
pub(crate) fn check_narrowing(
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

/// Deterministic structural relation ID for one quarantined cross-root edge,
/// so legacy migration replays exactly: the same snapshot always restores the
/// same relation identity. This ID is not owner-issued quarantine evidence.
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

/// Admits one structural root-transition record against a complete grant map.
///
/// This is the STRUCTURAL pass only (issue #2962, step 14): text/edge/root/
/// issuer/fence/revision/uniqueness correspondence between a record and the
/// live grants. It proves shape, never provenance. Nothing structural reaches
/// `GrantGraph::transitions` — a crossing becomes executable authority only
/// through [`AdmittedRootTransition::admit`], which additionally requires the
/// retained semantic decision, the validated Kernel activation receipt, and a
/// CURRENT owner readback.
fn admit_transition_record(
    grants: &BTreeMap<GrantId, CapabilityGrant>,
    record: &crate::root_transition::RootTransitionRecord,
    revision: u64,
) -> Result<(), AuthorityError> {
    record.validate_shape()?;
    if record.admitted_at_revision > revision {
        return Err(AuthorityError::InvalidField("root_transition.revision"));
    }
    let parent_id = GrantId::new(record.parent_grant_id.clone())?;
    let child_id = GrantId::new(record.child_grant_id.clone())?;
    let parent = grants
        .get(&parent_id)
        .ok_or(AuthorityError::InvalidField("root_transition.parent"))?;
    let child = grants
        .get(&child_id)
        .ok_or(AuthorityError::InvalidField("root_transition.child"))?;
    if child.parent_grant_id.as_ref() != Some(&parent_id) {
        return Err(AuthorityError::InvalidField("root_transition.edge"));
    }
    if parent.authority_root_ref != record.from_authority_root_ref
        || child.authority_root_ref != record.to_authority_root_ref
    {
        return Err(AuthorityError::InvalidField("root_transition.roots"));
    }
    if parent.holder.as_str() != record.issuer {
        return Err(AuthorityError::InvalidField("root_transition.issuer"));
    }
    if record.binding.state_fence != child.binding.state_fence {
        return Err(AuthorityError::FenceMismatch);
    }
    if !record
        .binding
        .authority_epoch
        .is_same_authority(&child.binding.authority_epoch)
    {
        return Err(AuthorityError::EpochMismatch);
    }
    Ok(())
}

pub const GRANT_GRAPH_RECOVERY_SCHEMA: &str = "eliot.authority.grant-graph-recovery";
/// Current grant-graph recovery contract version (issue #2962, step 9).
///
/// v1 is a closed legacy version: pre- and post-transition shapes were both
/// written as v1, and its `root_transitions` carried only self-agreeing
/// structural fields, so a v1 cross-root entry can never be re-interpreted as
/// owner-verified authority.
pub const GRANT_GRAPH_RECOVERY_VERSION: u16 = 2;

/// Legacy grant-graph recovery version. Retained only so a v1 payload can be
/// migrated deliberately, never silently upgraded to stronger semantics.
pub const LEGACY_GRANT_GRAPH_RECOVERY_VERSION: u16 = 1;

/// Complete durable state of a grant graph, in deterministic wire form.
///
/// `grants` carries admitted authority lineage only: a cross-root edge
/// without exact admitted [`AdmittedRootTransitionRecord`] evidence never
/// restores into the authority map.
///
/// #2962 versioning: v2 gives both trailing sections an EXPLICIT disposition
/// and removes the authority-sensitive `#[serde(default)]`. The transition
/// section carries the complete admitted-evidence commitment (the structural
/// record plus its canonical request digest, Kernel activation identity and
/// durable ORS record), so restore re-verifies it against CURRENT grants
/// instead of trusting copied fields; the quarantine section carries the same
/// explicit [`QuarantinedCrossRootRecord::disposition`] enum that restore
/// re-checks. The version is dispatched BEFORE any protected field is read, so
/// a v1 payload is never interpreted under v2 semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantGraphRecoverySnapshot {
    pub schema: String,
    pub version: u16,
    pub revision: u64,
    pub grants: Vec<GrantRecoveryRecord>,
    pub revoked: Vec<String>,
    /// Admitted root-transition evidence in transition-id order (#2962).
    /// Never defaulted: a missing section is a refusal, not an empty one.
    pub admitted_root_transitions: Vec<AdmittedRootTransitionRecord>,
    /// Inert quarantined cross-root relations in relation-id order (#2875).
    /// Never defaulted: a missing section is a refusal, not an empty one.
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
    /// Validates deterministic wire shape and internal graph consistency.
    ///
    /// This is not owner readback and does not authorize a transition-bearing
    /// snapshot for restoration. Public graph restore entry points refuse
    /// snapshots containing admitted root-transition evidence until a current
    /// owner readback path is available.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.validate_wire()?;
        GrantGraphRecoverySnapshot::restore_owned(self).map(|_| ())
    }

    /// Refuses to treat snapshot-local transition evidence as current owner
    /// readback. The original records stay in the caller-owned snapshot for
    /// audit and later reconciliation.
    fn require_owner_readback_for_restore(&self) -> Result<(), AuthorityError> {
        if self.admitted_root_transitions.is_empty() {
            Ok(())
        } else {
            Err(AuthorityError::StaleTransitionEvidence(
                "grant_graph_recovery.root_transition_owner_readback_required",
            ))
        }
    }

    fn validate_wire(&self) -> Result<(), AuthorityError> {
        if self.schema != GRANT_GRAPH_RECOVERY_SCHEMA {
            return Err(AuthorityError::InvalidField("grant_graph_recovery.schema"));
        }
        if !matches!(
            self.version,
            GRANT_GRAPH_RECOVERY_VERSION | LEGACY_GRANT_GRAPH_RECOVERY_VERSION
        ) {
            return Err(AuthorityError::InvalidField("grant_graph_recovery.version"));
        }
        if self.version != GRANT_GRAPH_RECOVERY_VERSION {
            return Err(AuthorityError::InvalidField(
                "grant_graph_recovery.version_legacy_unqualified",
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
        for row in &self.admitted_root_transitions {
            row.record.validate_shape()?;
            if let Some(previous) = previous
                && previous >= row.record.transition_id.as_str()
            {
                return Err(AuthorityError::InvalidField(
                    "grant_graph_recovery.admitted_root_transitions",
                ));
            }
            previous = Some(row.record.transition_id.as_str());
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

    /// Reconstructs graph state for internal consistency validation:
    /// admitted authority and inert quarantined relations (#2875 item 9,
    /// #2962). Stored transition rows stay unreadable without CURRENT owner
    /// evidence and migrate to quarantine with their lineage retained.
    /// Public restore entry points separately reject transition-bearing
    /// snapshots because this helper can check only snapshot-local
    /// consistency, not current owner readback.
    ///
    /// Grants whose parent edge stays inside one root restore into the
    /// authority map. A cross-root edge carries no admittable evidence in a
    /// snapshot-local pass — no CURRENT owner receipt is available — so its
    /// child migrates to an inert [`QuarantinedCrossRootRelation`] record
    /// with its full lineage retained, as do transitive descendants;
    /// migration is deterministic, so exact replay restores the exact same
    /// graph. A cross-root edge that is not even a narrowing is not lineage
    /// and is refused with [`AuthorityError::GrantNotNarrower`]. Explicit
    /// quarantined records restore as quarantined evidence only: a record
    /// that is not cross-root, disagrees with its parent's root, or names
    /// an admitted grant fails closed instead of being silently
    /// reinterpreted. A legacy cross-root child therefore can never restore
    /// as active authority.
    ///
    /// The internal consistency pass runs NO admission: a snapshot-local pass
    /// holds no CURRENT owner receipt, so every transition row stays
    /// unreadable and its child migrates to inert quarantine. Stored field
    /// equality is never owner readback and cannot authorize restoration.
    /// The public restore entry points reject transition-bearing snapshots
    /// before invoking this helper; the original input remains intact for
    /// audit and reconciliation. Re-admission runs only through
    /// [`AdmittedRootTransition::admit_restored`] with a CURRENT receipt plus
    /// CURRENT grants, revision, and fence.
    #[allow(
        clippy::too_many_lines,
        reason = "restore keeps evidence admission, partitioning, quarantine and revocation in one fail-closed sequence"
    )]
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
        // Structural pass over the transition section, then the unreadable
        // pass: structural correspondence alone never enters the transition
        // map, and a snapshot-local pass holds no CURRENT owner receipt, so
        // no row can satisfy owner readback here.
        for row in &snapshot.admitted_root_transitions {
            admit_transition_record(&full_map, &row.record, snapshot.revision)?;
        }
        let transitions: BTreeMap<(GrantId, GrantId), AdmittedRootTransition> = BTreeMap::new();
        let mut unreadable: BTreeSet<(GrantId, GrantId)> = BTreeSet::new();
        let mut transition_ids: BTreeSet<&str> = BTreeSet::new();
        for row in &snapshot.admitted_root_transitions {
            let record = &row.record;
            let parent_id = GrantId::new(record.parent_grant_id.clone())?;
            let child_id = GrantId::new(record.child_grant_id.clone())?;
            if !transition_ids.insert(record.transition_id.as_str()) {
                return Err(AuthorityError::IdentityConflict);
            }
            // Without a CURRENT validated receipt this row is unreadable
            // owner evidence, however self-consistent its stored fields are:
            // its child migrates to inert quarantine in `partition_restored`
            // instead of a silently activated crossing. Re-admission runs
            // only through `AdmittedRootTransition::admit_restored` with a
            // CURRENT receipt plus CURRENT grants, revision, and fence.
            unreadable.insert((parent_id, child_id));
        }
        let probe = GrantGraph {
            grants: full_map,
            revoked: BTreeSet::new(),
            revision: snapshot.revision,
            transitions,
            unreadable_transitions: unreadable,
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

pub(crate) fn grant_to_recovery_record(grant: &CapabilityGrant) -> GrantRecoveryRecord {
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
/// ID. Quarantine is not deletion — the full dependent lineage is
/// retained — but retaining a record never admits it for authority: this
/// type is never placed in an [`EffectiveCapabilityPath`], a supporting
/// introduction ref, or the admitted grant map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedCrossRootRelation {
    /// Deterministic structural relation ID for this exact edge; not a receipt.
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
    /// Authority binding read from the validated leaf grant on this path.
    /// This is kept path-local so issuance cannot combine authority from one
    /// delegation line with the binding from another.
    pub authority_binding: AuthorityBinding,
    /// Earliest expiry of any grant in this independently validated path.
    pub expires_at: LogicalTime,
}

/// Derived holder view. Authorization checks exact paths to avoid unsafe
/// cross-products between independent alternate paths. The graph constructs
/// snapshots and callers evaluate them through authorization query methods,
/// so a quarantined cross-root relation without an exact admitted transition
/// receipt cannot appear in a snapshot (#2875 items 3, 5; acceptance A2).
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

    /// Number of independently supporting effective paths in this snapshot.
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Graph revision whose current active paths produced this snapshot.
    pub const fn grant_graph_revision(&self) -> u64 {
        self.grant_graph_revision
    }

    /// Returns one exact supporting path for this operation/resource/effect
    /// tuple. A caller never combines fields from independent paths.
    pub fn supporting_path(
        &self,
        operation: &str,
        resource: &str,
        effect: EffectClass,
    ) -> Result<&EffectiveCapabilityPath, AuthorityError> {
        self.paths
            .iter()
            .find(|path| path.authority.allows(operation, resource, effect))
            .ok_or(AuthorityError::NoEffectivePath)
    }

    /// Issues one exact-use lease from an original validated capability path.
    ///
    /// The caller supplies only the use identity and obligation. The binding,
    /// holder, `WorkScope`, `Session`, and expiry are copied from the same
    /// effective path and the snapshot that `GrantGraph` admitted; caller-made
    /// bindings or path cross-products are not accepted.
    pub fn issue_action_lease(
        &self,
        lease_id: LeaseId,
        exact_idempotency_key: impl Into<String>,
        operation: impl Into<String>,
        resource: impl Into<String>,
        effect: EffectClass,
        receipt_obligations: Vec<ReceiptObligation>,
    ) -> Result<ActionLease, AuthorityError> {
        let operation = operation.into();
        let resource = resource.into();
        let path = self.supporting_path(&operation, &resource, effect)?;
        let authority_set = AuthoritySet::new(
            [operation],
            [resource],
            effect,
        )?;
        ActionLease::new(
            lease_id,
            self.holder.clone(),
            exact_idempotency_key,
            authority_set,
            path.authority_binding.clone(),
            self.work_scope.clone(),
            self.session.clone(),
            path.expires_at,
            1,
            receipt_obligations,
        )
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
/// it. The relation ID is the structural lookup key; the optional binding
/// is the CURRENT owner-qualified evidence for this exact edge, when the
/// owner supplied one. A binding whose disposition does not satisfy an
/// omission stays visible and inert here but never closes a denominator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedFrontierMember {
    /// Quarantined dependent identity.
    pub grant_id: GrantId,
    /// Crossing source identity.
    pub parent_grant_id: GrantId,
    /// Structural relation ID for this edge, retained as the lookup key.
    pub relation_id: String,
    /// CURRENT verified quarantine binding for this exact edge, when the
    /// closure was computed with owner-qualified evidence for it.
    pub binding: Option<VerifiedQuarantineBinding>,
}

impl QuarantinedFrontierMember {
    /// Closed quarantine disposition of this frontier member: the bound
    /// owner disposition when a CURRENT binding is present, else
    /// [`QuarantineDisposition::LegacyUnverified`]. A relation-only restore
    /// carries no binding, so it is explicitly legacy and unverified —
    /// visible and inert, unable to close a denominator — until a new
    /// explicit owner verification operation qualifies it.
    #[must_use]
    pub fn disposition(&self) -> QuarantineDisposition {
        self.binding.as_ref().map_or(
            QuarantineDisposition::LegacyUnverified,
            VerifiedQuarantineBinding::disposition,
        )
    }
}

/// Honest revocation-closure state (#2875 item 6).
///
/// A traversal that encounters a cross-scope omission keeps the exact
/// omission and dependent in the frontier and reports partial/unknown,
/// unless the owner supplied a CURRENT verified quarantine binding for
/// that exact edge. Only [`Complete`](Self::Complete) carries typed
/// omission evidence; a plain relation label is allowed only in
/// [`PartialOrUnknown`](Self::PartialOrUnknown) forensic detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationClosureState {
    /// Every encountered dependent is in the affected denominator, and
    /// every omitted cross-root dependent is bound to its CURRENT
    /// verified quarantine binding, in relation-id order. Each binding
    /// carries the exact parent/dependent binding plus the receipts
    /// needed to revalidate it.
    Complete {
        separately_quarantined: Vec<VerifiedQuarantineBinding>,
    },
    /// Recovery-required: the exact unresolved frontier plus the exact
    /// engine omissions in engine order. Structurally matching quarantine
    /// relation IDs may travel alongside as forensic details; they are not
    /// separate-quarantine evidence.
    PartialOrUnknown {
        frontier: Vec<String>,
        omissions: Vec<RevocationOmission>,
        separately_quarantined: Vec<String>,
    },
}

/// Typed revocation-closure verdict: the replayable transition/record the
/// durable descendant-closure fencing owner (#2100) consumes.
///
/// The record binds the exact operation that produced it: the same-root
/// denominator, the receipt-authorized cross-root descendants with their
/// authorizing receipts, the quarantine frontier with its CURRENT verified
/// bindings, every transition receipt the walk actually followed, the
/// snapshot revision, the State Fence (hence the authority epoch), the
/// traversal bounds the completeness claim was proven under, the engine's own
/// recomputed request digest, and the honest completeness state reconciling
/// the bounded engine outcome against the live graph.
///
/// `traversed_transitions` holds the crate's admitted transition evidence
/// itself, not a list of transition names. A member here can only be produced
/// by [`AdmittedRootTransition::admit`] or [`AdmittedRootTransition::admit_restored`],
/// each of which re-verifies an owner activation receipt against CURRENT
/// owner state, so every value in it — operation identity, idempotency key,
/// canonical request digest, graph snapshot, fence/epoch binding, Kernel
/// activation identity, durable ORS record, and the owner's own disposition —
/// was supplied by the persistence owner. This crate mints none of them and
/// cannot place an entry here that the owner did not commit, so the record
/// never reports a transition receipt it did not receive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationClosureVerdict {
    /// Revoked origin.
    pub origin: GrantId,
    /// Graph revision the verdict was computed at.
    pub revision: u64,
    /// Exact State Fence the walk and the bounded engine both ran under. The
    /// authority epoch travels inside it, so the record binds the epoch it was
    /// proven at rather than leaving the two to be re-derived by a consumer.
    pub state_fence: StateFence,
    /// Exact traversal bounds the completeness claim below was proven under. A
    /// completeness claim is meaningless without them: the same membership
    /// proven whole under wider bounds is a different proof.
    pub bounds: eliot_influence::RevocationBounds,
    /// Canonical request digest the bounded engine recomputed for the exact
    /// request it answered, over the request id, the origin, the reason, the
    /// fence, the declared completeness, and the qualified-edge multiset. It
    /// is read from the engine's own outcome after `verify_binding` re-derived
    /// and compared it, so it identifies this evaluation and not merely the
    /// root reference it started from. This crate does not compute it.
    pub request_digest: String,
    /// Origin authority root.
    pub authority_root_ref: String,
    /// Same-root denominator in parent-before-child order with the target
    /// first; element-wise equal to [`GrantGraph::delegated_closure`].
    pub members: Vec<GrantClosureMemberRef>,
    /// Receipt-authorized cross-root descendants in parent-before-child
    /// order; every member's authority derives through a crossing.
    pub authorized_cross_root: Vec<AuthorizedCrossRootMember>,
    /// Quarantined dependents encountered by the walk, each with its
    /// CURRENT verified binding when the owner supplied one. Members
    /// without a binding are explicitly legacy and unverified.
    pub quarantined_frontier: Vec<QuarantinedFrontierMember>,
    /// Admitted transition evidence for every crossing this walk followed, in
    /// transition-id order. Each entry is the owner's own admitted record; an
    /// entry here proves the crossing committed under the identity it names.
    pub traversed_transitions: Vec<AdmittedRootTransition>,
    /// Honest completeness state of this closure.
    pub state: RevocationClosureState,
}

/// The structural results of one authorized dependency walk, before the
/// bounded engine outcome is reconciled against them.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ClosureWalk {
    /// Authority root the walked origin belongs to.
    authority_root_ref: String,
    /// Same-root denominator, parent before child, origin first.
    members: Vec<GrantClosureMemberRef>,
    /// Receipt-authorized cross-root descendants with the transition
    /// identity that authorized each.
    authorized_cross_root: Vec<AuthorizedCrossRootMember>,
    /// Every reference the walk reached, including cross-root members.
    reached: BTreeSet<String>,
}

/// Adds one verdict's admitted crossing evidence to a denominator's transition
/// set, in transition-id order.
///
/// One transition identity, and one owner operation identity, may each appear
/// once. A repeat that carries different content is the I5.27
/// same-operation/changed-payload conflict and refuses whole, so a changed
/// payload is never unioned into a second crossing under an identity that
/// already committed different content. A repeat with identical content is one
/// crossing seen twice and is deduplicated. Every value compared here was
/// supplied by the persistence owner and re-verified at admission; nothing is
/// derived from the request being re-evaluated.
fn admit_traversed_transition(
    traversed: &mut BTreeMap<String, AdmittedRootTransition>,
    evidence: AdmittedRootTransition,
) -> Result<(), AuthorityError> {
    let conflicting = traversed.values().any(|known| {
        let same_transition = known.record().transition_id == evidence.record().transition_id;
        let same_operation = known.record().operation_id == evidence.record().operation_id;
        let same_digest = known.canonical_request_digest() == evidence.canonical_request_digest();
        if same_digest {
            // Identical content under one transition id is the same crossing
            // seen twice, and a shared transition id carrying a different
            // operation is a different crossing reusing the id.
            same_transition && !same_operation
        } else {
            // A different canonical request digest under a shared transition id
            // or a shared operation id is the conflict this refuses. Nothing
            // else is, and nothing else here can be.
            same_transition || same_operation
        }
    });
    if conflicting {
        return Err(AuthorityError::IdentityConflict);
    }
    let transition_id = evidence.record().transition_id.clone();
    traversed.entry(transition_id).or_insert(evidence);
    Ok(())
}

/// Owner-declared expected denominator for exactly one declared revocation
/// origin (#2966).
///
/// This is the single result every restored suppression is compared against
/// before any grant status changes. It is computed under the exact graph
/// revision and fence the restore is bound to, deduplicates by grant
/// identity, and keeps the retained root marker — the typed
/// [`RevocationOrigin`] — separately from the grant members. A retained
/// quarantine relation contributes forensic frontier evidence only and is
/// never active reachability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationDenominator {
    /// The one declared origin this denominator was computed for.
    pub origin: RevocationOrigin,
    /// Restored graph revision the denominator was computed at.
    pub revision: u64,
    /// Exact fence the denominator was computed at.
    pub state_fence: StateFence,
    /// Active grant members, deduplicated by grant identity, so a branching
    /// or converging descendant appears exactly once.
    pub members: BTreeSet<String>,
    /// Cross-root members that joined only through exact admitted `#2962`
    /// transition evidence, with the authorizing transition id. A raw
    /// transition DTO can never populate this.
    pub authorized_cross_root: Vec<AuthorizedCrossRootMember>,
    /// Retained quarantined dependents the walk reached; their relation ids
    /// are forensic labels, not members.
    pub quarantined_frontier: Vec<QuarantinedFrontierMember>,
    /// Admitted transition evidence for every crossing any contributing
    /// verdict followed, in transition-id order. Every value in an entry was
    /// supplied by the persistence owner; this crate mints none of them.
    pub traversed_transitions: Vec<AdmittedRootTransition>,
    /// Exact traversal bounds the completeness claim below was proven under.
    /// Without them the claim does not identify which proof it rests on.
    pub bounds: eliot_influence::RevocationBounds,
    /// Honest completeness of this denominator, reconciled against the
    /// bounded engine outcome. Anything but `Complete` denies it whole.
    pub completeness: RevocationClosureState,
}

/// The result of resolving one declared closure origin against the bound
/// graph. Every case is explicit, so the spelling of a reference never
/// decides a revocation kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BoundRevocationOrigin {
    /// The declared reference resolves to exactly one entity of this graph.
    Bound(RevocationOrigin),
    /// The declared reference names no entity of this graph: it belongs to a
    /// denominator this graph does not own.
    Foreign,
    /// The declared reference names both an admitted grant and an owned
    /// authority root here, so no single typed origin can be resolved from
    /// it and the closure is not a usable declaration.
    Ambiguous,
}

/// Closed operation kind of the canonical authority-revocation transition this
/// crate PREPARES. It is part of the canonical request preimage, so this
/// operation kind can never collide with another canonical operation under one
/// operation identity (I5.27).
pub const REVOCATION_TRANSITION_OPERATION_KIND: &str = "authority.revocation.activate";

/// The admitted operation identity ONE bounded revocation traversal runs under.
///
/// Every coordinate here is owner-supplied. This crate has no admitted task,
/// work scope, or observation receipt of its own — the graph is a pure
/// authority evaluator with no plan, no scope binding, and no Store readback —
/// so it cannot derive one and must not invent one. The fields are private and
/// [`Self::admit`] is the only constructor, so a value that exists has already
/// been refused if any coordinate was blank, control-bearing, or if its time
/// coordinate carried no causal `transaction_sequence`. `TaskId` and
/// `ReceiptId` are canonical by construction, so neither has a defaultable
/// path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationOperationIdentity {
    principal_ref: String,
    admitted_task: TaskId,
    work_scope_ref: String,
    observing_receipt: ReceiptId,
    operation_clock: ClockReading,
}

impl RevocationOperationIdentity {
    /// Binds the five admitted coordinates of one revocation operation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] for a blank or
    /// control-bearing `principal_ref`/`work_scope_ref`, and for an
    /// `operation_clock` that fails its own ordered-reading check or names no
    /// `transaction_sequence`. A host wall-clock reading is exactly the
    /// external timestamp that cannot become causal order, so it refuses here
    /// rather than reaching the bounded engine. No coordinate is defaulted
    /// here: an owner that has none cannot construct this value at all.
    pub fn admit(
        principal_ref: impl Into<String>,
        admitted_task: TaskId,
        work_scope_ref: impl Into<String>,
        observing_receipt: ReceiptId,
        operation_clock: ClockReading,
    ) -> Result<Self, AuthorityError> {
        let principal_ref = principal_ref.into();
        let work_scope_ref = work_scope_ref.into();
        validate_text(&principal_ref, "revocation_operation.principal_ref")?;
        validate_text(&work_scope_ref, "revocation_operation.work_scope_ref")?;
        operation_clock
            .validate()
            .map_err(|_| AuthorityError::InvalidField("revocation_operation.operation_clock"))?;
        if operation_clock.transaction_sequence.is_none() {
            return Err(AuthorityError::InvalidField(
                "revocation_operation.operation_clock",
            ));
        }
        Ok(Self {
            principal_ref,
            admitted_task,
            work_scope_ref,
            observing_receipt,
            operation_clock,
        })
    }
}

/// Disposition of one prepared authority-revocation transition, as reconciled
/// by the persistence owner that performs the canonical write.
///
/// Only [`Committed`](Self::Committed) reports a durable write.
/// [`Prepared`](Self::Prepared) is the state this crate leaves a transition in
/// before the owner has answered, and
/// [`UnknownOutcome`](Self::UnknownOutcome) is the owner saying it cannot tell
/// whether THIS operation identity committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTransitionDisposition {
    /// Prepared and not yet written; the owner supplied no durable receipt.
    Prepared,
    /// The owner proved this exact operation identity committed.
    Committed,
    /// The owner cannot tell whether this exact operation identity committed.
    UnknownOutcome,
}

/// The existing transition receipt, canonical write receipt, and
/// reconciliation coordinate the persistence owner actually holds for one
/// exact prepared operation identity.
///
/// This is supplied evidence, never a value this crate composes. The
/// `recorded_request_digest` is the canonical request hash the durable record
/// carries for the SAME operation identity; it is compared against the digest
/// this crate derives, so a receipt for changed content under one identity is
/// the I5.27 conflict rather than a commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationWriteReceipt {
    /// The existing transition/write receipt the owner holds.
    pub receipt: ReceiptIdentity,
    /// The owner's own reconciliation coordinate for that receipt.
    pub reconciliation: ReceiptIdentity,
    /// Canonical request hash the durable record carries for this exact
    /// operation identity.
    pub recorded_request_digest: String,
}

/// Everything the owner supplies to prepare the canonical revocation
/// transition for one declared origin.
///
/// The affected set is deliberately absent: it is derived from the
/// origin-bound closure this graph actually computes, never copied from a
/// caller list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationTransitionRequest {
    /// Stable canonical operation identity the persistence owner allocated.
    pub operation_id: String,
    /// Idempotency key of that exact operation.
    pub idempotency_key: String,
    /// Owner snapshot identity the transition is presented under.
    pub snapshot_id: SnapshotId,
    /// Exact State Fence, carrying the authority epoch, the owner presents
    /// this transition under.
    pub state_fence: StateFence,
    /// Exact traversal bounds the completeness claim must be proven under.
    pub bounds: eliot_influence::RevocationBounds,
    /// Why the owner is revoking the origin.
    pub reason: RevocationReason,
    /// The owner's reconciled disposition for this exact operation identity.
    pub disposition: RevocationTransitionDisposition,
    /// The existing transition/write receipt and reconciliation coordinate,
    /// when the owner holds one. Required by a committed disposition and
    /// refused for every other disposition.
    pub write_receipt: Option<RevocationWriteReceipt>,
    /// The admitted principal, task, work scope, observing receipt, and causal
    /// position the bounded closure is computed under. The graph holds no
    /// plan, scope binding, or Store readback of its own, so it can derive
    /// none of these and never does: they arrive from the owner, already
    /// refused by [`RevocationOperationIdentity::admit`] if incomplete.
    pub operation: RevocationOperationIdentity,
}

/// Canonical preimage of one prepared authority-revocation transition. Private
/// on purpose: it is the digest input, not a wire contract.
///
/// The receipt coordinates and the disposition are deliberately NOT in this
/// preimage: they are the owner's ANSWER about the transition, not the request
/// being written, so folding them in would make the digest differ between a
/// prepared and a committed presentation of one operation identity and break
/// exact replay.
#[derive(Serialize)]
struct RevocationTransitionCanonicalPreimage<'a> {
    operation_kind: &'static str,
    operation_id: &'a str,
    idempotency_key: &'a str,
    origin: &'a str,
    owner_namespace: &'a str,
    affected: &'a BTreeSet<String>,
    graph_revision: u64,
    snapshot_id: &'a str,
    authority_epoch: &'a EpochId,
    state_fence: &'a StateFence,
    bounds: &'a eliot_influence::RevocationBounds,
    reason: RevocationReason,
    unresolved: &'a BTreeSet<String>,
    separately_quarantined: &'a [String],
}

/// The canonical authority-revocation transition this crate is PREPARED to
/// emit, with every coordinate the replayability requirement names.
///
/// This is the prepared-transition DECISION, not the canonical envelope.
/// `eliot-canonical`'s `CanonicalWriteEnvelope` and `eliot-store-api`'s
/// `PreparedTransition`/`NamedMutationRequest` are the ONE governed write
/// path, they live outside this crate, and A12.3 forbids this pure evaluator
/// from becoming a second writer. What belongs here is the part A12.3 leaves
/// to the semantic owner: the typed, closed, content-bound decision of WHICH
/// canonical revocation transition the authority graph is prepared to emit,
/// which the canonical owner then serializes exactly once.
///
/// Every field is private and neither `Serialize` nor `Deserialize` is
/// derived, so a decoded or caller-authored value can never be a prepared
/// transition. Its only constructor re-derives the affected set from the
/// origin-bound closure, rechecks the fence and epoch against every affected
/// member, and compares any owner-supplied receipt against the canonical
/// request digest it computed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRevocationTransition {
    operation_id: String,
    idempotency_key: String,
    canonical_request_digest: String,
    origin: String,
    owner_namespace: String,
    affected: BTreeSet<String>,
    graph_revision: u64,
    snapshot_id: SnapshotId,
    authority_epoch: EpochId,
    state_fence: StateFence,
    bounds: eliot_influence::RevocationBounds,
    reason: RevocationReason,
    completeness: RevocationClosureState,
    disposition: RevocationTransitionDisposition,
    write_receipt: Option<RevocationWriteReceipt>,
}

impl PreparedRevocationTransition {
    /// Stable canonical operation identity this transition is prepared under.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Idempotency key of that exact operation.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Canonical request digest of the exact transition this crate prepared.
    #[must_use]
    pub fn canonical_request_digest(&self) -> &str {
        &self.canonical_request_digest
    }

    /// The one declared origin every affected grant was derived from.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Authority root the origin belongs to, proven to be one this graph owns.
    #[must_use]
    pub fn owner_namespace(&self) -> &str {
        &self.owner_namespace
    }

    /// The exact affected set the origin-bound closure derived, in
    /// grant-identity order. A caller cannot supply or extend it.
    #[must_use]
    pub const fn affected(&self) -> &BTreeSet<String> {
        &self.affected
    }

    /// Graph revision the affected set was derived at.
    #[must_use]
    pub const fn graph_revision(&self) -> u64 {
        self.graph_revision
    }

    /// Owner snapshot identity the transition is presented under.
    #[must_use]
    pub fn snapshot_id(&self) -> &str {
        self.snapshot_id.as_str()
    }

    /// Authority epoch the transition is proven at; it travels inside the
    /// bound State Fence and is compared against every affected member.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Exact State Fence the closure was proven under.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Exact traversal bounds the completeness claim was proven under.
    #[must_use]
    pub const fn bounds(&self) -> &eliot_influence::RevocationBounds {
        &self.bounds
    }

    /// Why the origin is being revoked, as the owner recorded it.
    #[must_use]
    pub const fn reason(&self) -> RevocationReason {
        self.reason
    }

    /// Honest completeness of the affected set. Preparation admits only a
    /// complete closure, so this is never partial.
    #[must_use]
    pub const fn completeness(&self) -> &RevocationClosureState {
        &self.completeness
    }

    /// The owner's reconciled disposition of this exact operation identity.
    #[must_use]
    pub const fn disposition(&self) -> RevocationTransitionDisposition {
        self.disposition
    }

    /// Whether this transition is reported as durably committed. True only
    /// for [`RevocationTransitionDisposition::Committed`], so a possible
    /// commit is never read as a commit.
    #[must_use]
    pub fn is_committed(&self) -> bool {
        matches!(self.disposition, RevocationTransitionDisposition::Committed)
    }

    /// The existing transition/write receipt and reconciliation coordinate the
    /// owner supplied, or the explicit absence while the transition is
    /// prepared or its outcome is unknown.
    #[must_use]
    pub fn write_receipt(&self) -> Option<&RevocationWriteReceipt> {
        self.write_receipt.as_ref()
    }
}

impl GrantGraph {
    /// Prepares the canonical authority-revocation transition for exactly one
    /// declared origin, binding every coordinate the replayability
    /// requirement names and NEVER committing it.
    ///
    /// The affected set is the one this graph ACTUALLY derives for that one
    /// origin under the owner's declared fence and bounds, through
    /// [`revocation_denominator_for_origin`](Self::revocation_denominator_for_origin).
    /// No caller-supplied membership is accepted anywhere on this path, so a
    /// transition can never name a grant the origin-bound closure does not
    /// reach, and a partial or unknown closure refuses instead of preparing a
    /// transition that over-claims.
    ///
    /// `prior` is the transition the owner already prepared or reconciled for
    /// the same origin, when it holds one. It is what makes replay and
    /// conflict real rather than assumed: a second presentation of the SAME
    /// operation identity with a different canonical request digest is the
    /// I5.27 conflict and performs no transition, and a prior whose outcome is
    /// unknown may only be re-presented under its OWN identity, never under a
    /// fresh one, because a possible commit is not a no-write.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidField`] for a blank operation
    /// identity or idempotency key, [`AuthorityError::FenceMismatch`] and
    /// [`AuthorityError::EpochMismatch`] when the presented fence or epoch
    /// disagrees with an affected member's live binding,
    /// [`AuthorityError::StaleTransitionEvidence`] when a receipt is presented
    /// under a disposition that does not report a commit, or when a committed
    /// transition would be walked back to prepared or unknown,
    /// [`AuthorityError::UnreconciledTransitionEvidence`] when a possible
    /// commit is re-presented without the owner's resolution,
    /// [`AuthorityError::IdentityConflict`] for the same operation identity
    /// with changed content and for a possible commit re-presented under a
    /// fresh identity, and [`AuthorityError::BoundedRevocation`] carrying the
    /// engine's own cause for an incomplete closure, invalid bounds, or an
    /// origin that resolves to no entity of this graph.
    pub fn prepare_revocation_transition(
        &self,
        origin: &RevocationOrigin,
        request: &RevocationTransitionRequest,
        prior: Option<&PreparedRevocationTransition>,
    ) -> Result<PreparedRevocationTransition, AuthorityError> {
        validate_text(&request.operation_id, "revocation_transition.operation_id")?;
        validate_text(
            &request.idempotency_key,
            "revocation_transition.idempotency_key",
        )?;
        request
            .state_fence
            .validate()
            .map_err(|_| AuthorityError::FenceMismatch)?;
        request
            .bounds
            .validate()
            .map_err(map_bounded_revocation_error)?;
        if let Some(prior) = prior {
            require_same_operation(prior, &request.operation_id, &request.idempotency_key)?;
            require_forward_only_disposition(prior, request.disposition)?;
        }
        // The declared origin is re-resolved against THIS graph, so a
        // reference that names no entity here — or two — refuses instead of
        // being read as a revocation of something else.
        let owner_namespace = self.require_bound_origin_namespace(origin)?;
        let denominator = self.revocation_denominator_for_origin(
            origin,
            &request.state_fence,
            &request.bounds,
            &request.operation,
        )?;
        let RevocationClosureState::Complete {
            separately_quarantined,
        } = &denominator.completeness
        else {
            return Err(map_bounded_revocation_error(
                eliot_influence::InfluenceError::IncompleteCoverage(
                    "revocation_transition.completeness",
                ),
            ));
        };
        let separately_quarantined: Vec<String> = separately_quarantined
            .iter()
            .map(|binding| binding.relation_id().to_owned())
            .collect();
        let affected = self.require_members_at_fence(&denominator, &request.state_fence)?;
        let unresolved = unresolved_references(&denominator.completeness);
        let canonical_request_digest = sha256_hex(
            &canonical_json_bytes(&RevocationTransitionCanonicalPreimage {
                operation_kind: REVOCATION_TRANSITION_OPERATION_KIND,
                operation_id: &request.operation_id,
                idempotency_key: &request.idempotency_key,
                origin: origin.as_str(),
                owner_namespace: &owner_namespace,
                affected: &affected,
                graph_revision: self.revision,
                snapshot_id: request.snapshot_id.as_str(),
                authority_epoch: &request.state_fence.authority_epoch,
                state_fence: &request.state_fence,
                bounds: &request.bounds,
                reason: request.reason,
                unresolved: &unresolved,
                separately_quarantined: &separately_quarantined,
            })
            .map_err(|_| {
                AuthorityError::InvalidField("revocation_transition.canonical_request_digest")
            })?,
        );
        let write_receipt = admit_write_receipt(request, &canonical_request_digest)?;
        Ok(PreparedRevocationTransition {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            canonical_request_digest,
            origin: origin.as_str().to_owned(),
            owner_namespace,
            affected,
            graph_revision: self.revision,
            snapshot_id: request.snapshot_id.clone(),
            authority_epoch: request.state_fence.authority_epoch.clone(),
            state_fence: request.state_fence.clone(),
            bounds: request.bounds.clone(),
            reason: request.reason,
            completeness: denominator.completeness,
            disposition: request.disposition,
            write_receipt,
        })
    }

    /// The exact affected membership, rechecked as admitted grants of THIS
    /// graph bound to the presented fence and the same authority epoch.
    ///
    /// The readback is against the live grants, never against a copy of a
    /// caller list: a closure proven against a fence or an authority epoch the
    /// graph no longer serves is not this transition, and a member this graph
    /// cannot resolve is a reconciliation problem to report rather than
    /// silently dropped from the denominator.
    fn require_members_at_fence(
        &self,
        denominator: &RevocationDenominator,
        fence: &StateFence,
    ) -> Result<BTreeSet<String>, AuthorityError> {
        let mut affected = BTreeSet::new();
        for member in &denominator.members {
            let grant_id = GrantId::new(member.as_str())?;
            let Some(grant) = self.grant(grant_id.as_str()) else {
                return Err(AuthorityError::MissingParent(grant_id));
            };
            if grant.binding.state_fence != *fence {
                return Err(AuthorityError::FenceMismatch);
            }
            if !grant
                .binding
                .authority_epoch
                .is_same_authority(&fence.authority_epoch)
            {
                return Err(AuthorityError::EpochMismatch);
            }
            affected.insert(member.clone());
        }
        if affected.is_empty() {
            return Err(AuthorityError::InvalidField(
                "revocation_transition.affected",
            ));
        }
        Ok(affected)
    }

    /// The authority root the one declared origin belongs to, proven to be an
    /// authority root THIS graph owns.
    fn require_bound_origin_namespace(
        &self,
        origin: &RevocationOrigin,
    ) -> Result<String, AuthorityError> {
        if !matches!(
            self.resolve_revocation_origin(origin.as_str()),
            Ok(BoundRevocationOrigin::Bound(bound)) if bound == *origin
        ) {
            return Err(map_bounded_revocation_error(
                eliot_influence::InfluenceError::UnverifiedRecovery("revocation_transition.origin"),
            ));
        }
        let namespace = match origin {
            RevocationOrigin::Grant(grant_id) => self
                .grant(grant_id.as_str())
                .map(|grant| grant.authority_root_ref.clone())
                .ok_or_else(|| AuthorityError::MissingParent(grant_id.clone()))?,
            RevocationOrigin::AuthorityRoot(root_ref) => root_ref.as_str().to_owned(),
        };
        self.owned_authority_root(namespace.as_str())
            .map(|owned| owned.as_str().to_owned())
            .map_err(|_| AuthorityError::InvalidField("revocation_transition.owner_namespace"))
    }
}

/// Rejects a second presentation that cannot be reconciled with the prior one
/// under the SAME operation identity.
fn require_same_operation(
    prior: &PreparedRevocationTransition,
    operation_id: &str,
    idempotency_key: &str,
) -> Result<(), AuthorityError> {
    if prior.operation_id != operation_id {
        if prior.disposition == RevocationTransitionDisposition::UnknownOutcome {
            // A possible commit is not a no-write: presenting the same work
            // under a fresh identity cannot conflict with the first attempt
            // and can apply it twice.
            return Err(AuthorityError::IdentityConflict);
        }
        return Ok(());
    }
    if prior.idempotency_key != idempotency_key {
        return Err(AuthorityError::IdentityConflict);
    }
    Ok(())
}

/// Rejects a presentation that would walk a concluded transition backwards.
///
/// A possible commit advances only to a committed presentation of that SAME
/// operation identity carrying the owner's own durable evidence; it never
/// becomes a no-write. A committed transition is the owner's own durable
/// record and is never re-presented as prepared or unknown, so no later
/// presentation can retract it.
fn require_forward_only_disposition(
    prior: &PreparedRevocationTransition,
    disposition: RevocationTransitionDisposition,
) -> Result<(), AuthorityError> {
    match prior.disposition {
        RevocationTransitionDisposition::Prepared => Ok(()),
        RevocationTransitionDisposition::UnknownOutcome
            if disposition == RevocationTransitionDisposition::Committed =>
        {
            Ok(())
        }
        RevocationTransitionDisposition::UnknownOutcome => Err(
            AuthorityError::UnreconciledTransitionEvidence("revocation_transition.outcome_unknown"),
        ),
        RevocationTransitionDisposition::Committed => Err(AuthorityError::StaleTransitionEvidence(
            "revocation_transition.committed_downgrade",
        )),
    }
}

/// Admits the owner's existing transition/write receipt and reconciliation
/// coordinate for this exact operation identity, or its explicit absence.
fn admit_write_receipt(
    request: &RevocationTransitionRequest,
    canonical_request_digest: &str,
) -> Result<Option<RevocationWriteReceipt>, AuthorityError> {
    let Some(receipt) = request.write_receipt.as_ref() else {
        if request.disposition == RevocationTransitionDisposition::Committed {
            // A committed claim with no durable receipt from the persistence
            // owner is a manufactured one. This crate reports no commit it
            // was not given evidence for.
            return Err(AuthorityError::StaleTransitionEvidence(
                "revocation_transition.write_receipt",
            ));
        }
        return Ok(None);
    };
    if request.disposition != RevocationTransitionDisposition::Committed {
        // A receipt under a disposition that does not report a commit is
        // evidence the owner and this crate disagree about, not a commit.
        return Err(AuthorityError::StaleTransitionEvidence(
            "revocation_transition.disposition",
        ));
    }
    validate_text(
        receipt.receipt.receipt_id.as_str(),
        "revocation_transition.receipt_id",
    )?;
    validate_digest(
        &receipt.receipt.canonical_sha256,
        "revocation_transition.canonical_sha256",
    )?;
    validate_text(
        receipt.reconciliation.receipt_id.as_str(),
        "revocation_transition.reconciliation_id",
    )?;
    validate_digest(
        &receipt.reconciliation.canonical_sha256,
        "revocation_transition.reconciliation_sha256",
    )?;
    // The receipt is bound to THIS operation by CONTENT: the canonical request
    // hash the durable record carries for that identity must equal the digest
    // derived here. Existence or shape proves nothing, and a same-identity
    // write of changed content is the conflict, never a commit.
    validate_digest(
        &receipt.recorded_request_digest,
        "revocation_transition.recorded_request_digest",
    )?;
    if receipt.recorded_request_digest != canonical_request_digest {
        return Err(AuthorityError::IdentityConflict);
    }
    Ok(Some(receipt.clone()))
}

/// `ELIOT_ARCH_OWNER`: ARCH-AUTH-01
/// Pure grant-lineage evaluator.
#[derive(Clone, Debug)]
pub struct GrantGraph {
    grants: BTreeMap<GrantId, CapabilityGrant>,
    revoked: BTreeSet<GrantId>,
    revision: u64,
    /// Verified crossing evidence, keyed by the exact parent/child edge. A
    /// member here is admitted authority and was produced by
    /// [`AdmittedRootTransition::admit`] or re-verified on restore; a decoded
    /// structural record can never be placed here.
    transitions: BTreeMap<(GrantId, GrantId), AdmittedRootTransition>,
    /// Transition-evidence rows that exist in the durable payload but no longer
    /// verify against CURRENT state. They authorize nothing; the child they
    /// name is migrated to an inert quarantined relation, and the edge is
    /// reported as an explicit unknown instead of being cleared.
    unreadable_transitions: BTreeSet<(GrantId, GrantId)>,
    quarantined: BTreeMap<String, QuarantinedCrossRootRelation>,
}

impl GrantGraph {
    /// Constructs a graph of ordinary same-root delegation (#2875 item 2).
    ///
    /// A child whose `authority_root_ref` differs from its parent's is
    /// rejected with [`AuthorityError::GrantNotNarrower`] before entering
    /// the graph; ordinary delegation stays inside one root. A separately
    /// authorized crossing requires [`Self::with_admitted_transitions`], which
    /// accepts only evidence a verified owner operation produced.
    pub fn from_grants(
        grants: impl IntoIterator<Item = CapabilityGrant>,
        revision: u64,
    ) -> Result<Self, AuthorityError> {
        Self::assemble(grants, BTreeMap::new(), BTreeSet::new(), revision)
    }

    /// Constructs a graph from ordinary same-root delegation plus crossings that
    /// already carry admitted owner evidence.
    ///
    /// #2962 step 7: the executable constructor takes
    /// [`AdmittedRootTransition`] and NOT a structural
    /// [`RootTransitionRecord`](crate::RootTransitionRecord). Because the
    /// admitted type has no public field, no `Deserialize` derive, and no
    /// constructor that skips the semantic-decision, Kernel-activation, and
    /// CURRENT-owner-readback gate, a caller-built or decoded record cannot
    /// authorize a cross-root edge. Every crossing still narrows on all four
    /// narrowing axes, so a transition authorizes the re-root, never widening.
    pub fn with_admitted_transitions(
        grants: impl IntoIterator<Item = CapabilityGrant>,
        admitted: impl IntoIterator<Item = AdmittedRootTransition>,
        revision: u64,
    ) -> Result<Self, AuthorityError> {
        let mut transitions: BTreeMap<(GrantId, GrantId), AdmittedRootTransition> = BTreeMap::new();
        for evidence in admitted {
            let record = evidence.record();
            let parent_id = GrantId::new(record.parent_grant_id.clone())?;
            let child_id = GrantId::new(record.child_grant_id.clone())?;
            // One transition identity may appear once, and one OWNER operation
            // identity may be bound to exactly one canonical request digest.
            // A second presentation of that operation identity carrying a
            // DIFFERENT digest is the I5.27 same-operation/changed-payload
            // conflict: the committed result stays authoritative, the new
            // content is refused, and no second crossing is admitted.
            let duplicate_identity = transitions.values().any(|known| {
                known.record().transition_id == record.transition_id
                    || (known.operation_id() == evidence.operation_id()
                        && known.canonical_request_digest() != evidence.canonical_request_digest())
            });
            if duplicate_identity
                || transitions
                    .insert((parent_id, child_id), evidence)
                    .is_some()
            {
                return Err(AuthorityError::IdentityConflict);
            }
        }
        Self::assemble(grants, transitions, BTreeSet::new(), revision)
    }

    /// Shared assembly: every public constructor funnels here, so no path can
    /// build a graph with an unauthorized crossing.
    fn assemble(
        grants: impl IntoIterator<Item = CapabilityGrant>,
        transitions: BTreeMap<(GrantId, GrantId), AdmittedRootTransition>,
        unreadable_transitions: BTreeSet<(GrantId, GrantId)>,
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
        for ((parent_id, child_id), evidence) in &transitions {
            let record = evidence.record();
            admit_transition_record(&by_id, record, revision)?;
            if record.parent_grant_id != parent_id.as_str()
                || record.child_grant_id != child_id.as_str()
            {
                return Err(AuthorityError::InvalidField("root_transition.edge"));
            }
        }
        let graph = Self {
            grants: by_id,
            revoked: BTreeSet::new(),
            revision,
            transitions,
            unreadable_transitions,
            quarantined: BTreeMap::new(),
        };
        graph.validate_cycles()?;
        graph.validate_edges()?;
        Ok(graph)
    }

    /// Exact admitted transition evidence for one delegation edge, if the
    /// owner admitted a root crossing on exactly this parent/child pair.
    pub fn transition_for_edge(
        &self,
        parent: &GrantId,
        child: &GrantId,
    ) -> Option<&AdmittedRootTransition> {
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

    /// Quarantine relation retained under one exact structural relation id,
    /// if any. The id is the lookup key only; it proves no owner decision.
    pub fn quarantine_by_relation(
        &self,
        relation_id: &str,
    ) -> Option<&QuarantinedCrossRootRelation> {
        self.quarantined.get(relation_id)
    }

    /// CURRENT parent grant of one quarantined edge: the admitted grant when
    /// the source is live authority, else the retained lineage of a
    /// quarantined ancestor. Commitment readback resolves the same lineage
    /// the restore checks did, so section order never affects the verdict.
    pub fn quarantine_parent_grant(&self, parent_id: &GrantId) -> Option<&CapabilityGrant> {
        self.grants.get(parent_id).or_else(|| {
            self.quarantined
                .values()
                .find(|known| known.child.grant_id == *parent_id)
                .map(|known| &known.child)
        })
    }

    /// Whether one grant identity is CURRENT admitted authority in this
    /// graph. A quarantined child is never admitted; its presence here
    /// would falsify any never-effective or fenced claim about it.
    pub fn grant_is_admitted(&self, grant_id: &GrantId) -> bool {
        self.grants.contains_key(grant_id)
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

    /// Whether one reference names an entity this graph owns — admitted
    /// authority, or lineage retained as quarantined evidence.
    ///
    /// A reference that names neither is not proven to belong to another
    /// graph's denominator; a lookup miss only proves that this graph holds
    /// no such entity, which is why a reference under a bound origin is
    /// bound to this namespace (see
    /// [`Self::admit_origin_bound_closure`]).
    pub(crate) fn names_in_graph(&self, reference: &str) -> bool {
        self.grant(reference).is_some()
            || self
                .quarantined
                .values()
                .any(|relation| relation.child.grant_id.as_str() == reference)
    }

    /// Whether this graph holds at least one admitted grant owned by exactly
    /// this authority root, and returns that typed root when it does.
    ///
    /// This is the only proof of graph/snapshot owner-namespace membership
    /// available to a pure restore: the namespace a committed closure was
    /// served under is an authority-root reference, and its membership is
    /// decided against the bound graph's own admitted grants. It is never
    /// inferred from a name prefix, from "it looks like a grant id", or from
    /// any free-form label.
    pub(crate) fn owned_authority_root(
        &self,
        reference: &str,
    ) -> Result<AuthorityRootRef, RevocationHistoryError> {
        let root_ref =
            AuthorityRootRef::new(reference).map_err(|_| RevocationHistoryError::UnknownHistory)?;
        if self
            .grants
            .values()
            .any(|grant| grant.authority_root_ref == root_ref.as_str())
        {
            Ok(root_ref)
        } else {
            Err(RevocationHistoryError::UnknownHistory)
        }
    }

    /// Resolves one declared closure origin against this graph, the only
    /// namespace a restore of this snapshot is bound to.
    ///
    /// The declared reference is never classified by its spelling, its
    /// prefix, or by "it matches a grant, otherwise it is a root". The two
    /// candidates are checked independently against the bound graph: it is
    /// a grant origin when this graph holds an admitted grant with exactly
    /// that identity, and an authority-root origin when this graph holds at
    /// least one admitted grant whose `authority_root_ref` is exactly that
    /// reference. A reference that satisfies neither is
    /// [`BoundRevocationOrigin::Foreign`], and a reference that satisfies
    /// both is [`BoundRevocationOrigin::Ambiguous`] and refuses — two
    /// entities of one graph claiming a single revocation declaration is not
    /// resolved by guessing which one the record meant.
    pub(crate) fn resolve_revocation_origin(
        &self,
        root_ref: &str,
    ) -> Result<BoundRevocationOrigin, RevocationHistoryError> {
        validate_text(root_ref, "revocation_origin")
            .map_err(|_| RevocationHistoryError::UnknownHistory)?;
        let grant_id = GrantId::new(root_ref).ok();
        let authority_root = AuthorityRootRef::new(root_ref).ok();
        match (
            grant_id.as_ref().filter(|id| self.grants.contains_key(*id)),
            authority_root.as_ref().filter(|root| {
                self.grants
                    .values()
                    .any(|grant| grant.authority_root_ref == root.as_str())
            }),
        ) {
            (Some(_), Some(_)) => Ok(BoundRevocationOrigin::Ambiguous),
            (Some(grant_id), None) => Ok(BoundRevocationOrigin::Bound(RevocationOrigin::Grant(
                grant_id.clone(),
            ))),
            (None, Some(root_ref)) => Ok(BoundRevocationOrigin::Bound(
                RevocationOrigin::AuthorityRoot(root_ref.clone()),
            )),
            (None, None) => Ok(BoundRevocationOrigin::Foreign),
        }
    }

    /// Computes the one expected revocation denominator for exactly one
    /// declared origin, under the exact graph revision and fence (#2966).
    ///
    /// A **grant origin** is evaluated once through
    /// [`revocation_closure_verdict`](Self::revocation_closure_verdict), so
    /// the denominator holds that grant's own same-root members and only the
    /// cross-root descendants reached through exact admitted transition
    /// evidence. An **authority-root origin** enumerates exactly the
    /// admitted grants that root owns in grant-id order, closes each one's
    /// authorized descendant paths through that same verdict owner, and
    /// deduplicates by grant identity, so a branching or converging
    /// descendant appears exactly once. The root marker stays on the typed
    /// [`RevocationOrigin`], separately from the grant members, and any
    /// retained quarantine relation contributes forensic frontier evidence
    /// only.
    ///
    /// The bounded traversal itself stays in `eliot-influence`; this is the
    /// graph owner's enumeration of it. Nothing here mints a receipt, a
    /// durable commitment, or a second graph, and the result is immutable:
    /// durable fencing remains with the Governor/Kernel owner (#2100).
    pub fn revocation_denominator_for_origin(
        &self,
        origin: &RevocationOrigin,
        fence: &StateFence,
        bounds: &eliot_influence::RevocationBounds,
        operation: &RevocationOperationIdentity,
    ) -> Result<RevocationDenominator, AuthorityError> {
        match origin {
            RevocationOrigin::Grant(grant_id) => {
                let verdict =
                    self.revocation_closure_verdict(grant_id, fence, bounds, operation)?;
                self.denominator_from_verdicts(origin, fence, bounds, [verdict])
            }
            RevocationOrigin::AuthorityRoot(root_ref) => {
                // `BTreeMap` iteration is grant-id ordered, so the union below
                // is deterministic across restarts and owners.
                let owned: Vec<GrantId> = self
                    .grants
                    .values()
                    .filter(|grant| grant.authority_root_ref == root_ref.as_str())
                    .map(|grant| grant.grant_id.clone())
                    .collect();
                let mut verdicts = Vec::with_capacity(owned.len());
                for grant_id in owned {
                    verdicts.push(
                        self.revocation_closure_verdict(&grant_id, fence, bounds, operation)?,
                    );
                }
                self.denominator_from_verdicts(origin, fence, bounds, verdicts)
            }
        }
    }

    /// Collapses the one verdict per declared origin into the single typed
    /// denominator recovery compares against, deduplicating by grant
    /// identity and keeping every honest partial/unknown frontier.
    ///
    /// The union is also where two contributing verdicts' transition evidence
    /// is reconciled. The same transition id contributed by two verdicts is one
    /// crossing, so it appears once; the same OWNER operation identity
    /// contributed twice with two different canonical request digests is the
    /// I5.27 same-operation/changed-payload conflict and refuses whole, so a
    /// changed payload can never be unioned into a second crossing under an
    /// identity that already committed different content.
    fn denominator_from_verdicts(
        &self,
        origin: &RevocationOrigin,
        state_fence: &StateFence,
        bounds: &eliot_influence::RevocationBounds,
        verdicts: impl IntoIterator<Item = RevocationClosureVerdict>,
    ) -> Result<RevocationDenominator, AuthorityError> {
        let mut members = BTreeSet::new();
        let mut authorized_cross_root: BTreeMap<String, AuthorizedCrossRootMember> =
            BTreeMap::new();
        let mut quarantined_frontier: BTreeMap<String, QuarantinedFrontierMember> = BTreeMap::new();
        let mut traversed: BTreeMap<String, AdmittedRootTransition> = BTreeMap::new();
        let mut frontier = BTreeSet::new();
        let mut omissions = Vec::new();
        let mut bound: BTreeMap<String, VerifiedQuarantineBinding> = BTreeMap::new();
        let mut forensic: BTreeSet<String> = BTreeSet::new();
        let mut partial = false;
        for verdict in verdicts {
            members.extend(
                verdict
                    .members
                    .iter()
                    .map(|member| member.grant_id.to_string()),
            );
            for member in &verdict.authorized_cross_root {
                members.insert(member.grant_id.to_string());
                authorized_cross_root.insert(member.grant_id.to_string(), member.clone());
            }
            for member in &verdict.quarantined_frontier {
                quarantined_frontier.insert(member.grant_id.to_string(), member.clone());
            }
            for evidence in verdict.traversed_transitions {
                admit_traversed_transition(&mut traversed, evidence)?;
            }
            match verdict.state {
                RevocationClosureState::Complete {
                    separately_quarantined: listed,
                } => {
                    for binding in listed {
                        forensic.insert(binding.relation_id().to_owned());
                        bound.insert(binding.relation_id().to_owned(), binding);
                    }
                }
                RevocationClosureState::PartialOrUnknown {
                    frontier: listed_frontier,
                    omissions: listed_omissions,
                    separately_quarantined: listed,
                } => {
                    partial = true;
                    frontier.extend(listed_frontier);
                    omissions.extend(listed_omissions);
                    forensic.extend(listed);
                }
            }
        }
        let completeness = if partial {
            RevocationClosureState::PartialOrUnknown {
                frontier: frontier.into_iter().collect(),
                omissions,
                separately_quarantined: forensic.into_iter().collect(),
            }
        } else {
            RevocationClosureState::Complete {
                separately_quarantined: bound.into_values().collect(),
            }
        };
        Ok(RevocationDenominator {
            origin: origin.clone(),
            revision: self.revision,
            state_fence: state_fence.clone(),
            members,
            authorized_cross_root: authorized_cross_root.into_values().collect(),
            quarantined_frontier: quarantined_frontier.into_values().collect(),
            traversed_transitions: traversed.into_values().collect(),
            bounds: bounds.clone(),
            completeness,
        })
    }

    /// Marks one grant revoked without replaying history.
    pub(crate) fn apply_restored_revocation(&mut self, grant_id: &GrantId) {
        self.revoked.insert(grant_id.clone());
    }

    /// Emits the complete durable graph: admitted authority, revoked set,
    /// admitted transition evidence, and inert quarantined relations. A
    /// quarantined relation re-emits into the quarantine section only, so
    /// snapshot/recovery/restart preserve the quarantine invariant and can
    /// never reactivate a legacy cross-root child as active authority.
    ///
    /// The emitted transition section is the COMPLETE admitted-evidence
    /// commitment of every crossing this graph still authorizes. Evidence that
    /// failed restore-time verification is re-emitted only as an inert
    /// quarantined relation: it is never promoted back into the transition
    /// section, so a dropped or unreadable row cannot be repaired by writing
    /// the snapshot again.
    pub fn recovery_snapshot(&self) -> Result<GrantGraphRecoverySnapshot, AuthorityError> {
        let grants = self.grants.values().map(grant_to_recovery_record).collect();
        let mut admitted_root_transitions: Vec<AdmittedRootTransitionRecord> = self
            .transitions
            .values()
            .map(AdmittedRootTransition::to_recovery_record)
            .collect();
        admitted_root_transitions
            .sort_by(|left, right| left.record.transition_id.cmp(&right.record.transition_id));
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
            admitted_root_transitions,
            quarantined_cross_root,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Restores graph state from a recovery snapshot.
    ///
    /// Snapshots with admitted root-transition records fail closed until a
    /// current owner readback path can confirm those records.
    pub fn from_recovery_snapshot(
        snapshot: &GrantGraphRecoverySnapshot,
    ) -> Result<Self, AuthorityError> {
        snapshot.validate_wire()?;
        snapshot.require_owner_readback_for_restore()?;
        GrantGraphRecoverySnapshot::restore_owned(snapshot)
    }

    /// Declared recovery contract version of one payload, decided BEFORE any
    /// protected field is interpreted (issue #2962, step 9).
    ///
    /// A v1 payload is legacy/unqualified: its transition section carried only
    /// self-agreeing structural fields, so it can never satisfy v2 restore.
    /// Dispatch on this value first, exactly as
    /// [`Self::from_recovery_snapshot_with_revocation_history`] dispatches on
    /// schema and version before any other wire field.
    #[must_use]
    pub const fn recovery_contract_version(snapshot: &GrantGraphRecoverySnapshot) -> u16 {
        snapshot.version
    }

    /// Restores a recovery snapshot under explicit CURRENT revocation-history
    /// evidence, applying all applicable committed revocations before any
    /// grant becomes effective.
    ///
    /// Transition-bearing snapshots refuse until their transition evidence is
    /// confirmed by current owner readback; revocation history is not a
    /// substitute for that readback.
    ///
    /// `None` history refuses with
    /// [`RevocationHistoryError::MissingHistory`]: unavailable history is
    /// not absence of revocation and never restores as an empty closure.
    /// Stale (fence or revision drift) and unknown (invalid, unordered, or
    /// non-revoked closure; unresolvable origin or dependent reference)
    /// evidence refuse likewise, as does one closure identity reused with
    /// changed content. Suppressed grants are retained with their full
    /// lineage and join the restored revoked set,
    /// so neither a revoked origin nor its dependent grants can revive; the
    /// exact suppressed set and reasons are reported in the outcome.
    /// Unrelated valid grants restore exactly as the snapshot carries them.
    ///
    /// #2966 production order, and the order is the guarantee: decode and
    /// shape-check the history, restore the snapshot, resolve each closure's
    /// ONE typed [`RevocationOrigin`] against this graph, compute that
    /// origin's expected [`RevocationDenominator`], compare the committed
    /// membership against it, and only then derive the suppression
    /// projection and apply it. Every refusal happens before the first
    /// suppression exists, so a failure leaves the restored graph exactly
    /// as the snapshot carried it and never presents a partial projection
    /// as applied.
    ///
    /// The production recheck refuses by named cause, so a caller can tell
    /// the failure classes apart instead of reading one untyped refusal.
    /// [`UnsupportedSchema`](eliot_influence::InfluenceError::UnsupportedSchema)
    /// names a snapshot whose declared schema or version is not the supported
    /// one (decided before any other wire field is validated);
    /// [`UnverifiedRecovery`](eliot_influence::InfluenceError::UnverifiedRecovery)
    /// names a committed closure whose declared origin this graph cannot
    /// relate to its own lineage while the closure still names in-graph
    /// targets;
    /// [`IncompleteCoverage`](eliot_influence::InfluenceError::IncompleteCoverage)
    /// names a denominator that could not be proven whole inside the declared
    /// bounds;
    /// [`TargetDrift`](eliot_influence::InfluenceError::TargetDrift) names a
    /// reachable in-graph target the committed closure left unrepresented; and
    /// [`RevocationHistoryError::OriginTargetMismatch`] names the opposite
    /// failure — an in-graph target the committed closure claims that the one
    /// declared origin cannot reach at all. The mismatch is a distinct typed
    /// variant, not a string folded into a bounded cause, because an extra
    /// target is exactly the case that must never be reinterpreted as a
    /// second revocation origin.
    /// [`RevocationHistoryError::IdentityConflict`] names one closure
    /// identity presented twice with changed content, or one crossing that
    /// closure depends on re-presented under a single owner operation
    /// identity with a different canonical request digest: the committed
    /// result is authoritative and nothing is applied.
    ///
    /// The legacy [`from_recovery_snapshot`](Self::from_recovery_snapshot)
    /// preserves its exact prior behavior for previously-admitted callers.
    ///
    /// `operation` is the admitted principal, task, work scope, observing
    /// receipt, and causal position the recheck runs under. The graph holds no
    /// plan, scope binding, or Store readback of its own, so it cannot derive
    /// one: the recovery owner supplies it, and the bounded engine refuses a
    /// traversal whose identity omits it. Without it this path cannot recheck
    /// anything, and "recheck nothing" is not the same as "no revocation".
    pub fn from_recovery_snapshot_with_revocation_history(
        snapshot: &GrantGraphRecoverySnapshot,
        history: Option<&crate::RevocationHistoryEvidence>,
        operation: &RevocationOperationIdentity,
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
        if !matches!(
            snapshot.version,
            GRANT_GRAPH_RECOVERY_VERSION | LEGACY_GRANT_GRAPH_RECOVERY_VERSION
        ) {
            return Err(RevocationHistoryError::BoundedRevocation(
                eliot_influence::InfluenceError::UnsupportedSchema("grant_graph_recovery.version"),
            ));
        }
        if snapshot.version != GRANT_GRAPH_RECOVERY_VERSION {
            return Err(RevocationHistoryError::BoundedRevocation(
                eliot_influence::InfluenceError::UnsupportedSchema(
                    "grant_graph_recovery.version_legacy_unqualified",
                ),
            ));
        }
        snapshot
            .validate_wire()
            .map_err(RevocationHistoryError::InvalidSnapshot)?;
        snapshot
            .require_owner_readback_for_restore()
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
        // #2966: the origin-bound comparison runs before any `SuppressedGrant`
        // exists. Every refusal on this path returns before
        // `apply_restored_revocation` is ever called, so the restored graph is
        // left exactly as the snapshot carried it.
        let mut admitted: Vec<AdmittedRevocationClosure> = Vec::with_capacity(closures.len());
        for closure in &closures {
            admitted.push(graph.admit_origin_bound_closure(
                closure,
                &evidence.state_fence,
                operation,
            )?);
        }
        let suppressed = derive_suppressions(&graph, &admitted);
        for entry in &suppressed {
            if let Ok(grant_id) = GrantId::new(entry.grant_id.clone()) {
                graph.apply_restored_revocation(&grant_id);
            }
        }
        Ok(GrantRestoreOutcome { graph, suppressed })
    }

    /// Validates one committed revocation closure against the denominator of
    /// exactly one declared origin, and admits it only when the whole
    /// origin-to-affected relation holds.
    ///
    /// A closure whose declared origin names no entity of this graph
    /// refuses outright, whether or not it names in-graph targets: a
    /// lookup miss proves nothing about another graph's denominator, and
    /// partitioning multi-graph history by owner namespace is the durable
    /// history owner's obligation before authority recovery, not a silent
    /// skip inside it. Likewise, a dependent reference under a *bound*
    /// origin that resolves to nothing in this namespace is unknown
    /// evidence, never a no-op; only the closure's own origin reference
    /// is exempt, because its namespace membership was already proven by
    /// the bound resolution itself.
    ///
    /// Four decisions, all reached from
    /// [`from_recovery_snapshot_with_revocation_history`](Self::from_recovery_snapshot_with_revocation_history)
    /// before any suppression is derived:
    ///
    /// 1. the declared origin resolves against this graph to exactly one
    ///    typed [`RevocationOrigin`] — a grant or an authority root, never a
    ///    guess read from the reference's spelling — and the declared owner
    ///    namespace is an authority root THIS graph owns that the declared
    ///    origin belongs to. An origin that resolves to none, or to two,
    ///    refuses, and so does a namespace this graph does not own or that the
    ///    origin does not belong to: a reference under a foreign namespace is
    ///    foreign evidence, never a silent skip. This is the A0.3 hard
    ///    boundary "restoration of revoked influence after recovery" refused
    ///    by cause instead of accepted unrecheckable;
    /// 2. the expected denominator for that one origin must be complete, and
    ///    it is computed under the traversal bounds the EVIDENCE declared —
    ///    this crate mints no bounds of its own here.
    ///    [`revocation_denominator_for_origin`](Self::revocation_denominator_for_origin)
    ///    evaluates the declared origin exactly once and reconciles the
    ///    bounded engine outcome against the live graph, following same-root
    ///    and admitted-crossing parent links and preserving omitted
    ///    cross-scope dependents as unresolved frontier entries, so a partial
    ///    verdict still refuses under I15.7's explicit incomplete-coverage
    ///    rule and an omitted dependent without owner-qualified quarantine
    ///    evidence is never silently cleared. The declared disposition and
    ///    the declared omissions are compared against that recomputed
    ///    completeness: a closure that does not declare itself complete, or
    ///    that declares an omission the recomputed denominator does not also
    ///    report, refuses under the same typed cause;
    /// 3. every in-graph target the closure names must be a member of that
    ///    one denominator. An in-graph target outside it is
    ///    [`RevocationHistoryError::OriginTargetMismatch`]: a
    ///    record-supplied `dependent_refs` member never becomes a second
    ///    implicit revocation origin, and it is never folded into
    ///    `TargetDrift`, which means a reachable target the closure omitted.
    ///    A dependent reference that resolves to nothing in this graph is
    ///    unknown evidence, never a silent skip;
    /// 4. every reachable in-graph member must be represented by the
    ///    committed membership — named directly, or owned by the declared
    ///    authority root whose retained marker stands for it — otherwise
    ///    the closure under-claims its transitive descendants and the
    ///    stored target set drifted. A suppressed ancestor never stands in
    ///    for an omitted descendant: no different historical affected set
    ///    is reconstructed under the same closure identity.
    ///
    /// Descendant completeness is checked against that one origin result.
    /// The declared origin is never re-traversed from each supplied member:
    /// doing so is what let a record-supplied target act as its own origin.
    pub(crate) fn admit_origin_bound_closure(
        &self,
        closure: &ValidatedRevocationClosure,
        fence: &StateFence,
        operation: &RevocationOperationIdentity,
    ) -> Result<AdmittedRevocationClosure, RevocationHistoryError> {
        // The declared owner namespace is proven against this graph's own
        // admitted grants, never read from the reference's spelling, and the
        // declared origin must belong to it. A closure served under a
        // namespace this graph does not own is unknown evidence: the durable
        // history owner pre-partitions multi-graph history by namespace, and
        // an unpartitioned row is not silently reinterpreted as this graph's.
        let owner_namespace = self.owned_authority_root(&closure.owner_namespace)?;
        let origin = match self.resolve_revocation_origin(&closure.root_ref)? {
            BoundRevocationOrigin::Bound(origin) => origin,
            BoundRevocationOrigin::Foreign => {
                if closure
                    .affected
                    .iter()
                    .any(|reference| self.names_in_graph(reference))
                {
                    return Err(RevocationHistoryError::BoundedRevocation(
                        eliot_influence::InfluenceError::UnverifiedRecovery(
                            "recovery.closure_origin",
                        ),
                    ));
                }
                return Err(RevocationHistoryError::UnknownHistory);
            }
            BoundRevocationOrigin::Ambiguous => {
                return Err(RevocationHistoryError::UnknownHistory);
            }
        };
        // The declared origin must belong to the declared owner namespace: a
        // grant origin is owned by that root, and a root origin IS that root.
        let origin_namespace = match &origin {
            RevocationOrigin::Grant(grant_id) => self
                .grant(grant_id.as_str())
                .map(|grant| grant.authority_root_ref.as_str()),
            RevocationOrigin::AuthorityRoot(root_ref) => Some(root_ref.as_str()),
        };
        if origin_namespace != Some(owner_namespace.as_str()) {
            return Err(RevocationHistoryError::UnknownHistory);
        }
        // The admission bounds are the bounds the EVIDENCE declared. A
        // completeness claim proven under different bounds than the ones
        // committed is a different proof, so this call site mints none.
        let bounds = closure.bounds.clone();
        // The declared disposition is the committed closure's own honesty
        // statement, and only a complete claim is admissible: I15.7 requires
        // incomplete coverage to be explicit, and recovery refuses it.
        if closure.disposition != RevocationEvidenceDisposition::Complete {
            return Err(RevocationHistoryError::BoundedRevocation(
                eliot_influence::InfluenceError::IncompleteCoverage(
                    "recovery.closure_declared_disposition",
                ),
            ));
        }
        let denominator = self
            .revocation_denominator_for_origin(&origin, fence, &bounds, operation)
            .map_err(|error| match error {
                // A crossing this closure depends on was presented twice under
                // one owner operation identity with different content. That is
                // the I5.27 conflict, and it stays a conflict here: naming it as
                // unknown history would tell the caller the record is
                // unclassifiable rather than that the SAME operation was
                // re-presented with a changed payload.
                AuthorityError::IdentityConflict => {
                    RevocationHistoryError::IdentityConflict(ClosureIdentityConflict {
                        closure_id: closure.closure_id.clone(),
                        field: "recovery.closure_crossing_evidence",
                    })
                }
                other => map_bounded_history_error(other),
            })?;
        // A denominator that is not complete is a bounded prefix, so the
        // committed affected set cannot be compared against it at all.
        if !matches!(
            denominator.completeness,
            RevocationClosureState::Complete { .. }
        ) {
            return Err(RevocationHistoryError::BoundedRevocation(
                eliot_influence::InfluenceError::IncompleteCoverage("recovery.closure_verdict"),
            ));
        }
        // The declared omissions must reconcile with the recomputed
        // denominator's own unresolved set. A committed closure that declares
        // it omitted a dependent is not a whole denominator and refuses under
        // the same typed cause; a whole denominator must declare none.
        if closure.omissions != unresolved_references(&denominator.completeness) {
            return Err(RevocationHistoryError::BoundedRevocation(
                eliot_influence::InfluenceError::IncompleteCoverage("recovery.closure_omissions"),
            ));
        }
        for reference in &closure.affected {
            // The origin reference itself is exempt: its namespace
            // membership was already proven by the bound resolution above
            // (a grant origin names an admitted grant; an authority-root
            // origin is the retained marker, never a grant member). Every
            // other affected reference is a dependent claim and must
            // resolve in this namespace.
            let known = self.names_in_graph(reference);
            if !known && reference != &closure.root_ref {
                return Err(RevocationHistoryError::UnknownHistory);
            }
            if known && !denominator.members.contains(reference.as_str()) {
                return Err(RevocationHistoryError::OriginTargetMismatch(
                    OriginTargetMismatch {
                        closure_id: closure.closure_id.clone(),
                        origin: origin.clone(),
                        target: reference.clone(),
                    },
                ));
            }
        }
        if self
            .unrepresented_member(closure, &origin, &denominator)
            .is_some()
        {
            return Err(RevocationHistoryError::BoundedRevocation(
                eliot_influence::InfluenceError::TargetDrift("recovery.closure_affected"),
            ));
        }
        AdmittedRevocationClosure::admit(closure, origin, owner_namespace, denominator)
    }

    /// The first denominator member the committed closure leaves
    /// unrepresented, if any.
    ///
    /// A member is represented only when the committed membership names it
    /// directly, or when the declared origin is the authority root that
    /// owns it. A represented ancestor never stands in for an omitted
    /// descendant: the committed origin is always a member of the affected
    /// set and an ancestor of every denominator member, so an ancestor
    /// walk would accept every omission and the drift refusal would be
    /// dead. A required reachable descendant omitted from a committed
    /// complete closure therefore stays `TargetDrift`, and no different
    /// historical affected set is reconstructed under the old closure ID.
    fn unrepresented_member(
        &self,
        closure: &ValidatedRevocationClosure,
        origin: &RevocationOrigin,
        denominator: &RevocationDenominator,
    ) -> Option<String> {
        for member in &denominator.members {
            if closure.affected.contains(member.as_str()) {
                continue;
            }
            if let RevocationOrigin::AuthorityRoot(root_ref) = origin
                && self
                    .grant(member.as_str())
                    .is_some_and(|grant| grant.authority_root_ref == root_ref.as_str())
            {
                continue;
            }
            return Some(member.clone());
        }
        None
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

    /// Fences one owner-declared grant closure in this graph, in a single
    /// revision step.
    ///
    /// `members` is the exact parent-before-child membership the owner itself
    /// declared for this closure — the same set the durable closure receipt
    /// commits and the Kernel already fenced. This method never re-derives
    /// membership, so it cannot widen a fence, and it never narrows one either:
    /// every declared member is fenced, including a member that also carries a
    /// declared alternate path, because the surviving exact use of such a
    /// member is admitted by the Kernel against its independent covering root
    /// and not by this projection.
    ///
    /// A target or member this graph cannot resolve refuses instead of being
    /// skipped: a grant absent from the recovered graph is a reconciliation
    /// problem to report, never evidence that it needs no fence. The refusal
    /// happens before any mutation, so a refused call leaves the graph exactly
    /// as it was.
    pub fn revoke_declared_closure(
        &mut self,
        target: &GrantId,
        members: &[String],
    ) -> Result<(), AuthorityError> {
        if !self.grants.contains_key(target) {
            return Err(AuthorityError::MissingParent(target.clone()));
        }
        let mut declared = Vec::with_capacity(members.len());
        for member in members {
            let grant_id = GrantId::new(member.clone())?;
            if !self.grants.contains_key(&grant_id) {
                return Err(AuthorityError::MissingParent(grant_id));
            }
            declared.push(grant_id);
        }
        for grant_id in declared {
            self.revoked.insert(grant_id);
        }
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
    /// Receipt-authorized cross-root descendants and structural quarantine
    /// relations are enumerated separately by
    /// [`revocation_closure_verdict`](Self::revocation_closure_verdict),
    /// which carries authorizing receipts and forensic relation IDs. A
    /// structural quarantine label cannot authorize omission for the durable
    /// fencing owner (#2100).
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
    /// authorized (same-root; the transitions map stays empty without
    /// CURRENT re-admission) and whose parent admitted
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
                    // Evidence that failed CURRENT verification (`unreadable`)
                    // authorizes nothing: the edge is refused exactly like an
                    // absent one, so the child migrates to inert quarantine.
                    if edge_is_authorized(parent, grant, &self.transitions)
                        && !self
                            .unreadable_transitions
                            .contains(&(parent_id.clone(), grant.grant_id.clone()))
                    {
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
        // Drop crossings orphaned by quarantine: a crossing whose parent or
        // child no longer names an admitted grant is never consulted (all
        // lookups key on in-map pairs). Snapshot-local restore admits no
        // crossing at all, so this only states the invariant.
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
    ///
    /// A relation-only restore carries no owner evidence, so the relation
    /// is explicitly [`LegacyUnverified`](QuarantineDisposition::LegacyUnverified)
    /// at the verdict layer: visible and inert, unable to close a
    /// denominator. It becomes current only through a new explicit owner
    /// verification operation; this restore never reinterprets it.
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
    /// which binds every omitted dependent to its CURRENT verified
    /// quarantine binding or reports an explicit partial/unknown state.
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
        operation: &RevocationOperationIdentity,
    ) -> Result<eliot_influence::BoundedRevocationOutcome, AuthorityError> {
        if !self.grants.contains_key(origin) {
            return Err(AuthorityError::MissingParent(origin.clone()));
        }
        let edges = self.qualified_influence_edges();
        let request = BoundedRevocationRequest {
            request_id: format!("transitive-revocation:{}", origin.as_str()),
            root_ref: origin.as_str().to_owned(),
            // The admitted principal, task, work scope, observing receipt and
            // causal position are the OWNER's, never this crate's. A12.5 ties
            // a dependent's ceiling to its source, and I5.27 defines
            // idempotency over canonical bytes: an operation whose identity
            // omitted them would yield the same digest for two different
            // principals, tasks, or observations. They travel with the
            // request and the engine re-freezes them, so nothing here is
            // defaulted, derived from the origin, or read from a clock.
            principal_ref: operation.principal_ref.clone(),
            admitted_task: operation.admitted_task.clone(),
            work_scope_ref: operation.work_scope_ref.clone(),
            observing_receipt: operation.observing_receipt.clone(),
            operation_clock: operation.operation_clock,
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
        // The receipt is bound to THIS request and THESE bounds by content
        // before any of its affected set is reconciled against the structural
        // walk below. `revoke_bounded_page` returns a complete outcome that
        // carries no continuation, so without this check the affected set,
        // frontier and omissions of a complete page were attributable to no
        // operation at all: only the root reference named anything.
        outcome
            .verify_binding(&request, bounds)
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
            // Every page is re-bound to the same operation before the loop
            // reads its completeness: a resumed page that answered a
            // different request, graph snapshot, bound set, reason or fence
            // refuses here rather than extending the closure.
            outcome
                .verify_binding(&request, bounds)
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

    /// Qualifies every grant edge the graph currently knows, plus each
    /// retained quarantined relation, as a cross-scope influence edge.
    fn qualified_influence_edges(&self) -> Vec<QualifiedInfluenceEdge> {
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
        // erasure; the verdict binds an omission only to a CURRENT
        // verified quarantine binding and otherwise preserves the exact
        // omission and dependent frontier.
        for relation in self.quarantined.values() {
            edges.push(QualifiedInfluenceEdge::cross_scope(
                relation.parent_grant_id.as_str().to_owned(),
                relation.child.grant_id.as_str().to_owned(),
            ));
        }
        edges
    }

    /// Collects the quarantined dependents whose edge source the walk
    /// reached, attaching the CURRENT verified binding for each edge the
    /// owner qualified. Members without a binding are explicitly legacy
    /// and unverified; they never establish a complete omission.
    fn collect_quarantined_frontier(
        &self,
        reached: &BTreeSet<String>,
        bindings: &BTreeMap<String, VerifiedQuarantineBinding>,
    ) -> Vec<QuarantinedFrontierMember> {
        let mut quarantined_frontier = Vec::new();
        for relation in self.quarantined.values() {
            if reached.contains(relation.parent_grant_id.as_str()) {
                quarantined_frontier.push(QuarantinedFrontierMember {
                    grant_id: relation.child.grant_id.clone(),
                    parent_grant_id: relation.parent_grant_id.clone(),
                    relation_id: relation.relation_id.clone(),
                    binding: bindings.get(&relation.relation_id).cloned(),
                });
            }
        }
        quarantined_frontier
    }

    /// Binds one cross-scope omission to its CURRENT verified quarantine
    /// binding: the owner-qualified evidence for the exact omitted
    /// source/dependent edge. A structural relation match alone binds
    /// nothing; only a binding for that exact edge whose disposition
    /// satisfies an omission qualifies.
    fn bind_quarantine_omission(
        &self,
        omission: &RevocationOmission,
        bindings: &BTreeMap<String, VerifiedQuarantineBinding>,
    ) -> Option<VerifiedQuarantineBinding> {
        let source = GrantId::new(omission.edge_source.as_str()).ok()?;
        let dependent = GrantId::new(omission.edge_dependent.as_str()).ok()?;
        let relation = self.quarantine_for_edge(&source, &dependent)?;
        let binding = bindings.get(&relation.relation_id)?;
        if !binding.satisfies_omission()
            || binding.parent_grant_id() != &source
            || binding.child_grant_id() != &dependent
        {
            return None;
        }
        Some(binding.clone())
    }

    /// Whether one recorded cross-scope omission is a genuine cross-root
    /// omission for this restored graph.
    ///
    /// The dedicated cross-scope influence relation is declared for every
    /// retained quarantined edge, and partition-time migration admits a
    /// descendant of a quarantined grant without re-testing the crossing
    /// (`restore_quarantine_record` does test it, `migrate_to_quarantine`
    /// only tests narrowing). A dependent this graph records under the SAME
    /// authority root as the omission's source is therefore reachable
    /// inside one root and is not a cross-scope omission at all:
    /// discharging it would drop an in-root dependent out of the closure
    /// denominator, so a revoked origin's own root could keep a live
    /// descendant. Revocation cannot narrow the declared root either.
    ///
    /// The crossing question is decided by the crate's one existing owner,
    /// [`crosses_authority_root`], over the lineage
    /// [`quarantine_parent_grant`](Self::quarantine_parent_grant) resolves
    /// for both sides, so this check cannot hold a different meaning of
    /// "different root" than edge declaration, the verdict walk, and the
    /// restore partition. An omission whose source or dependent this graph
    /// does not record keeps the pre-existing treatment: a lookup miss
    /// proves nothing about a crossing, so the omission still needs its own
    /// CURRENT binding to discharge.
    fn omission_crosses_authority_root(&self, omission: &RevocationOmission) -> bool {
        let (Ok(source), Ok(dependent)) = (
            GrantId::new(omission.edge_source.as_str()),
            GrantId::new(omission.edge_dependent.as_str()),
        ) else {
            return true;
        };
        let (Some(source_root), Some(dependent_root)) = (
            self.quarantine_parent_grant(&source)
                .map(|grant| grant.authority_root_ref.as_str()),
            self.quarantine_parent_grant(&dependent)
                .map(|grant| grant.authority_root_ref.as_str()),
        ) else {
            return true;
        };
        crosses_authority_root(source_root, dependent_root)
    }

    /// Reconciles one bounded engine outcome against the structural walk
    /// (#2875 item 6): the engine's affected set must match the reached set
    /// exactly, and every cross-scope omission must cross an authority root
    /// AND bind to a CURRENT verified quarantine binding. Returns the
    /// frontier refs, the bound omission bindings in relation-id order, the
    /// forensic relation labels, and whether the verdict is
    /// partial/unknown.
    ///
    /// An absent, stale, revoked, or mismatched binding preserves the exact
    /// frontier/omission and makes the verdict partial/unknown. A matching
    /// structural relation ID is returned only as forensic detail.
    fn reconcile_engine_outcome(
        &self,
        outcome: &eliot_influence::BoundedRevocationOutcome,
        reached: &BTreeSet<String>,
        unbound: BTreeSet<String>,
        bindings: &BTreeMap<String, VerifiedQuarantineBinding>,
    ) -> (
        BTreeSet<String>,
        BTreeMap<String, VerifiedQuarantineBinding>,
        BTreeSet<String>,
        bool,
    ) {
        let mut frontier_refs: BTreeSet<String> = outcome.frontier.iter().cloned().collect();
        let mut bound: BTreeMap<String, VerifiedQuarantineBinding> = BTreeMap::new();
        let mut forensic: BTreeSet<String> = BTreeSet::new();
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
                    // A cross-scope omission is legitimate only when the
                    // omitted dependent really leaves the omission source's
                    // authority root. A dependent under the same root is
                    // inside the declared scope, so it is never a legitimate
                    // omission: no binding discharges it, its exact
                    // reference is retained in the frontier, and the verdict
                    // stays partial/unknown. The check can only refuse a
                    // discharge, never grant one.
                    if !self.omission_crosses_authority_root(omission) {
                        frontier_refs.insert(omission.edge_dependent.clone());
                        partial = true;
                        continue;
                    }
                    if let (Ok(source), Ok(dependent)) = (
                        GrantId::new(omission.edge_source.as_str()),
                        GrantId::new(omission.edge_dependent.as_str()),
                    ) && let Some(relation) = self.quarantine_for_edge(&source, &dependent)
                    {
                        forensic.insert(relation.relation_id.clone());
                    }
                    if let Some(binding) = self.bind_quarantine_omission(omission, bindings) {
                        bound.insert(binding.relation_id().to_owned(), binding);
                    } else {
                        frontier_refs.insert(omission.edge_dependent.clone());
                        // No CURRENT verified binding for this exact edge,
                        // so the omission stays unresolved and the verdict
                        // stays partial/unknown.
                        partial = true;
                    }
                }
                _ => {
                    frontier_refs.insert(omission.edge_dependent.clone());
                    partial = true;
                }
            }
        }
        (frontier_refs, bound, forensic, partial)
    }

    /// Resolves the owner evidence authorizing one followed cross-root
    /// crossing, and records that evidence for the verdict.
    ///
    /// Returns the transition identity the crossing was authorized by, or
    /// `None` after adding the dependent to `unbound`. A crossing is
    /// authorized only by the owner's own admitted record, and only while
    /// that record carries the owner's committed disposition. Admission
    /// stores the receipt's disposition verbatim and refuses every other
    /// value, so this is the readback of that invariant exactly where a
    /// crossing would otherwise let a dependent into the affected set:
    /// absent evidence, or evidence whose disposition is anything but
    /// committed, leaves the dependent unresolved and the verdict
    /// partial/unknown instead of quietly fencing or clearing it.
    ///
    /// Everything recorded in `traversed` is the owner's admitted record
    /// itself, so the verdict restates the receipt the owner supplied rather
    /// than a name this crate composed.
    fn committed_crossing_evidence(
        &self,
        parent: &GrantId,
        child: &GrantId,
        traversed: &mut BTreeMap<String, AdmittedRootTransition>,
        unbound: &mut BTreeSet<String>,
    ) -> Option<String> {
        let authorized = self
            .transition_for_edge(parent, child)
            .filter(|evidence| evidence.disposition() == RootTransitionDisposition::Committed)
            .map(|evidence| {
                let transition_id = evidence.record().transition_id.clone();
                traversed.insert(transition_id.clone(), evidence.clone());
                transition_id
            });
        if authorized.is_none() {
            unbound.insert(child.as_str().to_owned());
        }
        authorized
    }

    /// Computes the honest revocation-closure verdict for one grant (#2875
    /// items 6, 7): the exact denominator the durable fencing owner (#2100)
    /// consumes.
    ///
    /// Without owner-qualified evidence every cross-scope omission stays
    /// unresolved, so this entry point reports partial/unknown for any
    /// closure that encounters one. Owners that hold CURRENT verified
    /// quarantine bindings use
    /// [`revocation_closure_verdict_with_quarantine`](Self::revocation_closure_verdict_with_quarantine).
    pub fn revocation_closure_verdict(
        &self,
        origin: &GrantId,
        fence: &StateFence,
        bounds: &eliot_influence::RevocationBounds,
        operation: &RevocationOperationIdentity,
    ) -> Result<RevocationClosureVerdict, AuthorityError> {
        self.revocation_closure_verdict_with_quarantine(
            origin,
            fence,
            bounds,
            &BTreeMap::new(),
            operation,
        )
    }

    /// Structural walk of one origin's authorized dependency closure.
    ///
    /// Returns the same-root denominator in parent-before-child order with
    /// the origin first, the receipt-authorized cross-root descendants with
    /// the transition identity that authorized each, and every reference the
    /// walk reached. A dependent the walk cannot authorize on committed
    /// owner evidence is recorded in `unresolved` rather than skipped, so the
    /// verdict that consumes this walk stays partial/unknown. The admitted
    /// transition evidence for every followed crossing is recorded in
    /// `traversals` as the owner's own record.
    fn walk_authorized_closure(
        &self,
        origin: &GrantId,
        traversals: &mut BTreeMap<String, AdmittedRootTransition>,
        unresolved: &mut BTreeSet<String>,
    ) -> Result<ClosureWalk, AuthorityError> {
        let target = self
            .grants
            .get(origin)
            .ok_or_else(|| AuthorityError::MissingParent(origin.clone()))?;
        // Stack discipline of `delegated_closure` (grant-id-ordered children,
        // parent before child), extended across receipt-authorized crossings.
        // `crossed` marks members reached through at least one crossing;
        // `authorizing` carries the nearest crossing above the entry.
        let mut members = vec![GrantClosureMemberRef {
            grant_id: target.grant_id.clone(),
            parent_grant_id: target.parent_grant_id.clone(),
        }];
        let mut authorized_cross_root = Vec::new();
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
                    unresolved.insert(child.grant_id.as_str().to_owned());
                    continue;
                }
                let edge_crosses =
                    crosses_authority_root(&node.authority_root_ref, &child.authority_root_ref);
                let child_authorizing = if edge_crosses {
                    match self.committed_crossing_evidence(
                        &node.grant_id,
                        &child.grant_id,
                        traversals,
                        unresolved,
                    ) {
                        Some(transition_id) => Some(transition_id),
                        None => continue,
                    }
                } else {
                    authorizing.clone()
                };
                reached.insert(child.grant_id.as_str().to_owned());
                if crossed || edge_crosses {
                    let Some(receipt_id) = child_authorizing.clone() else {
                        unresolved.insert(child.grant_id.as_str().to_owned());
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
        Ok(ClosureWalk {
            authority_root_ref: target.authority_root_ref.clone(),
            members,
            authorized_cross_root,
            reached,
        })
    }

    /// Computes the honest revocation-closure verdict for one grant (#2875
    /// items 6, 7) with CURRENT owner-qualified quarantine evidence: the
    /// exact denominator the durable fencing owner (#2100) consumes.
    ///
    /// The structural walk follows authorized inheritance — same-root and
    /// receipt-covered edges — from the origin, recording the same-root
    /// denominator, the receipt-authorized cross-root descendants with
    /// their authorizing receipts, the admitted owner evidence of every
    /// traversed transition, and the quarantined dependents encountered with
    /// their CURRENT verified bindings. The bounded engine outcome is
    /// reconciled against that walk: completeness requires the engine's
    /// affected set to match the reached set exactly, every cross-scope
    /// omission to leave the omission source's authority root, and every such
    /// omission to bind to a CURRENT verified quarantine binding. Anything
    /// less — an unfinished traversal, a nonempty frontier, a same-root
    /// dependent recorded as cross-scope, an unbound omission, or a
    /// denominator mismatch — is an explicit partial/unknown state with the
    /// exact frontier and omissions, never an omission-labelled success.
    ///
    /// The graph consumes already-qualified evidence only: it looks
    /// bindings up by exact relation id and rechecks the edge, but it
    /// cannot construct a binding from a relation id alone.
    pub fn revocation_closure_verdict_with_quarantine(
        &self,
        origin: &GrantId,
        fence: &StateFence,
        bounds: &eliot_influence::RevocationBounds,
        bindings: &BTreeMap<String, VerifiedQuarantineBinding>,
        operation: &RevocationOperationIdentity,
    ) -> Result<RevocationClosureVerdict, AuthorityError> {
        let mut traversed: BTreeMap<String, AdmittedRootTransition> = BTreeMap::new();
        let mut unbound: BTreeSet<String> = BTreeSet::new();
        let walk = self.walk_authorized_closure(origin, &mut traversed, &mut unbound)?;
        let quarantined_frontier = self.collect_quarantined_frontier(&walk.reached, bindings);
        let outcome = self.transitive_revocation_closure(origin, fence, bounds, operation)?;
        let (frontier_refs, bound, forensic, partial) =
            self.reconcile_engine_outcome(&outcome, &walk.reached, unbound, bindings);
        // Read before the omissions move below: this is the bounded engine's
        // own recomputed digest for the exact request it answered, already
        // re-bound to this request and these bounds by `verify_binding`.
        let request_digest = outcome.request_digest.clone();
        let state = if partial {
            RevocationClosureState::PartialOrUnknown {
                frontier: frontier_refs.into_iter().collect(),
                omissions: outcome.omissions,
                separately_quarantined: forensic.into_iter().collect(),
            }
        } else {
            RevocationClosureState::Complete {
                separately_quarantined: bound.into_values().collect(),
            }
        };
        Ok(RevocationClosureVerdict {
            origin: origin.clone(),
            revision: self.revision,
            state_fence: fence.clone(),
            bounds: bounds.clone(),
            request_digest,
            authority_root_ref: walk.authority_root_ref,
            members: walk.members,
            authorized_cross_root: walk.authorized_cross_root,
            quarantined_frontier,
            traversed_transitions: traversed.into_values().collect(),
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
        let mut expires_at = leaf.expires_at;
        loop {
            self.validate_active(cursor, work_scope, session, now)?;
            expires_at = expires_at.min(cursor.expires_at);
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
            authority_binding: leaf.binding.clone(),
            expires_at,
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
    /// omission naming the exact edge position. The verdict retains the
    /// dependent in its frontier and remains partial; a matching structural
    /// relation ID is forensic detail only. Revocation cannot widen scope or
    /// effect.
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
