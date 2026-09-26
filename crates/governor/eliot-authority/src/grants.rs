use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::StateFence;
use eliot_influence::{
    BoundedRevocationRequest, ClosureCompleteness, InfluenceEdgeDisposition, QualifiedInfluenceEdge,
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

pub const GRANT_GRAPH_RECOVERY_SCHEMA: &str = "eliot.authority.grant-graph-recovery";
pub const GRANT_GRAPH_RECOVERY_VERSION: u16 = 1;

/// Complete durable state of a grant graph, in deterministic wire form.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantGraphRecoverySnapshot {
    pub schema: String,
    pub version: u16,
    pub revision: u64,
    pub grants: Vec<GrantRecoveryRecord>,
    pub revoked: Vec<String>,
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
        GrantGraphRecoverySnapshot::restore_owned(self.revision, &self.grants, self.revoked.clone())
            .map(|_| ())
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
        Ok(())
    }

    fn restore_owned(
        revision: u64,
        records: &[GrantRecoveryRecord],
        revoked: Vec<String>,
    ) -> Result<GrantGraph, AuthorityError> {
        let grants = records
            .iter()
            .map(grant_from_recovery_record)
            .collect::<Result<Vec<_>, AuthorityError>>()?;
        let mut graph = GrantGraph::from_grants(grants, revision)?;
        for revoked in revoked {
            let grant_id = GrantId::new(revoked)?;
            if !graph.grants.contains_key(&grant_id) {
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

/// `ELIOT_ARCH_OWNER`: ARCH-AUTH-01
/// Pure grant-lineage evaluator.
#[derive(Clone, Debug)]
pub struct GrantGraph {
    grants: BTreeMap<GrantId, CapabilityGrant>,
    revoked: BTreeSet<GrantId>,
    revision: u64,
}

impl GrantGraph {
    pub fn from_grants(
        grants: impl IntoIterator<Item = CapabilityGrant>,
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
        let graph = Self {
            grants: by_id,
            revoked: BTreeSet::new(),
            revision,
        };
        graph.validate_cycles()?;
        graph.validate_edges()?;
        Ok(graph)
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

    pub fn recovery_snapshot(&self) -> Result<GrantGraphRecoverySnapshot, AuthorityError> {
        let grants = self
            .grants
            .values()
            .map(|grant| GrantRecoveryRecord {
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
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn from_recovery_snapshot(
        snapshot: GrantGraphRecoverySnapshot,
    ) -> Result<Self, AuthorityError> {
        snapshot.validate_wire()?;
        let GrantGraphRecoverySnapshot {
            revision,
            grants,
            revoked,
            schema: _,
            version: _,
        } = snapshot;
        GrantGraphRecoverySnapshot::restore_owned(revision, &grants, revoked)
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
    /// The legacy [`from_recovery_snapshot`](Self::from_recovery_snapshot)
    /// preserves its exact prior behavior for previously-admitted callers.
    pub fn from_recovery_snapshot_with_revocation_history(
        snapshot: GrantGraphRecoverySnapshot,
        history: Option<&crate::RevocationHistoryEvidence>,
    ) -> Result<GrantRestoreOutcome, RevocationHistoryError> {
        snapshot
            .validate_wire()
            .map_err(RevocationHistoryError::InvalidSnapshot)?;
        let evidence = history.ok_or(RevocationHistoryError::MissingHistory)?;
        let closures = evidence.require_current()?;
        let GrantGraphRecoverySnapshot {
            revision,
            grants,
            revoked,
            schema: _,
            version: _,
        } = snapshot;
        let mut graph = GrantGraphRecoverySnapshot::restore_owned(revision, &grants, revoked)
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
        // Fail-closed recheck: every engine-reachable in-graph descendant of
        // an affected in-graph grant must already be suppressed. The engine
        // traverses exactly the same-root parent links as
        // `derive_suppressions`, so this holds by construction on complete
        // evidence and refuses when a closure under-claims its transitive
        // descendants. Affected references naming no grant in this graph
        // belong to another graph's denominator and refuse nothing.
        let suppressed_ids: BTreeSet<&str> = suppressed
            .iter()
            .map(|entry| entry.grant_id.as_str())
            .collect();
        for closure in &closures {
            for affected_ref in &closure.affected {
                let Ok(grant_id) = GrantId::new(affected_ref.as_str()) else {
                    continue;
                };
                if graph.grant(grant_id.as_str()).is_none() {
                    continue;
                }
                let outcome = graph
                    .transitive_revocation_closure(
                        &grant_id,
                        &evidence.state_fence,
                        &eliot_influence::RevocationBounds::default_bounds(),
                    )
                    .map_err(map_bounded_history_error)?;
                if !outcome.complete
                    || !outcome.frontier.is_empty()
                    || outcome.omissions.iter().any(|omission| {
                        matches!(
                            omission.cause,
                            eliot_influence::OmissionCause::BoundsExhausted
                        )
                    })
                {
                    return Err(RevocationHistoryError::UnknownHistory);
                }
                for engine_ref in &outcome.affected_refs {
                    if graph.grant(engine_ref.as_str()).is_some()
                        && !suppressed_ids.contains(engine_ref.as_str())
                    {
                        return Err(RevocationHistoryError::UnknownHistory);
                    }
                }
            }
        }
        for entry in &suppressed {
            if let Ok(grant_id) = GrantId::new(entry.grant_id.clone()) {
                graph.apply_restored_revocation(&grant_id);
            }
        }
        Ok(GrantRestoreOutcome { graph, suppressed })
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
                        && grant.authority_root_ref == authority_root_ref
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
    /// Every delegation link on the origin's authority root becomes one
    /// qualified influence edge with
    /// [`PermittedCurrent`](InfluenceEdgeDisposition::PermittedCurrent)
    /// disposition: live-graph edges are current by construction. A link that
    /// leaves the origin's authority root is still declared, with
    /// [`CrossScope`](InfluenceEdgeDisposition::CrossScope) disposition, so the
    /// evaluator records a typed cross-scope omission for it instead of the
    /// link vanishing from the denominator. Such a dependent is quarantined
    /// from this traversal: it is never followed, never revoked, and never part
    /// of the affected set, mirroring
    /// [`delegated_closure`](Self::delegated_closure) and the rule that
    /// revocation cannot widen scope.
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
        let target = self
            .grants
            .get(origin)
            .ok_or_else(|| AuthorityError::MissingParent(origin.clone()))?;
        let authority_root_ref = target.authority_root_ref.clone();
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
            // Delegation that leaves the origin's authority root is never
            // followed, and it is never dropped without a trace either. The
            // edge is declared with the `CrossScope` disposition so the
            // evaluator records a typed `CrossScope` omission naming the exact
            // source-bound edge position instead of an absent edge the reader
            // cannot distinguish from an unexamined one. Revocation cannot
            // widen scope or effect, so a cross-root dependent is quarantined
            // from this traversal: it is not propagated, is not revoked, and
            // never enters the affected set. Quarantine is not erasure — the
            // grant keeps its full lineage in the snapshot and the omission is
            // the only evidence that this traversal refused to follow it.
            let disposition = if grant.authority_root_ref == authority_root_ref {
                InfluenceEdgeDisposition::PermittedCurrent
            } else {
                InfluenceEdgeDisposition::CrossScope
            };
            edges.push(QualifiedInfluenceEdge {
                source_ref: parent_id.as_str().to_owned(),
                dependent_ref: grant.grant_id.as_str().to_owned(),
                disposition,
            });
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

    fn validate_edges(&self) -> Result<(), AuthorityError> {
        for child in self.grants.values() {
            let Some(parent_id) = &child.parent_grant_id else {
                continue;
            };
            let parent = self
                .grants
                .get(parent_id)
                .ok_or_else(|| AuthorityError::MissingParent(parent_id.clone()))?;
            if child.authority_root_ref != parent.authority_root_ref
                || child.issuer != parent.holder
                || !child.authority.is_strict_subset_of(&parent.authority)
                || child.expires_at > parent.expires_at
                || child.max_uses > parent.max_uses
            {
                return Err(AuthorityError::GrantNotNarrower(child.grant_id.clone()));
            }
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
        let restored = GrantGraph::from_recovery_snapshot(snapshot.clone())?;
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
        let restored = GrantGraph::from_recovery_snapshot(snapshot.clone())?;
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
            GrantGraph::from_recovery_snapshot(zero_revision),
            Err(AuthorityError::InvalidField("grant_graph_revision"))
        ));

        let mut unknown_revocation = base.clone();
        unknown_revocation.revoked.push("grant:unknown".to_owned());
        unknown_revocation.revoked.sort();
        assert!(matches!(
            GrantGraph::from_recovery_snapshot(unknown_revocation),
            Err(AuthorityError::MissingParent(id)) if id.as_str() == "grant:unknown"
        ));

        let mut duplicate = base.clone();
        duplicate.grants.push(duplicate.grants[1].clone());
        assert!(matches!(
            GrantGraph::from_recovery_snapshot(duplicate),
            Err(AuthorityError::InvalidField("grant_graph_recovery.grants"))
        ));

        let mut cycle = base.clone();
        cycle.grants[0].parent_grant_id = Some("grant:child".to_owned());
        assert!(matches!(
            GrantGraph::from_recovery_snapshot(cycle),
            Err(AuthorityError::GrantCycle(_))
        ));

        let mut widened = base;
        widened.grants[0].allowed_operations = vec!["read".to_owned(), "write".to_owned()];
        widened.grants[0].allowed_resources =
            vec!["resource:a".to_owned(), "resource:b".to_owned()];
        widened.grants[0].max_effect = EffectClass::ExternalEffect;
        let widened_error = GrantGraph::from_recovery_snapshot(widened)
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
            GrantGraph::from_recovery_snapshot(empty_snapshot.clone())?.recovery_snapshot()?,
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
