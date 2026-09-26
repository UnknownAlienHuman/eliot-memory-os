//! Owner-neutral v2 row-identity, comparison, and snapshot-closure shapes.
//!
//! Issue #246 freezes three facts the v1 surface conflates:
//!
//! * source spelling is lossless and never an implicit comparison policy
//!   ([`CueSourceValue`]);
//! * a comparison key cites its exact scope, kind, mode, and normalized value
//!   ([`CueComparisonKey`]);
//! * a published snapshot carries a frozen denominator
//!   ([`CueProjectionDenominator`]).
//!
//! Row identity is one frozen versioned function
//! ([`cue_row_id`], also reachable as [`SnapshotMember::row_id`]) binding
//! scope, kind, mode, normalized comparison key, target identity, and the
//! identity-contract revision ([`CONTRACT_REVISION`]). Two rows that differ in
//! any one dimension never share an identity.
//!
//! [`ConversionDisposition`] records what a v1 migration did without claiming
//! admission: replay preserves old bytes/identity, conversion issues a v2 row
//! id alongside the preserved legacy id, and rejection names a bounded reason.
//! None of the three strengthens support, applicability, accessibility,
//! influence, or lifecycle.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{
    CONTRACT_REVISION, CueContractError, Digest, RelationEdgeId, SnapshotMember, SourceHandle,
    TargetHandle, bounds,
    normalization::{CueKind, MatchMode},
};

/// Maximum rows one closed validation may join to snapshot members.
const MAX_CLOSED_ROWS: usize = crate::MAX_SNAPSHOT_MEMBERS;

/// Maximum edge weights one closed validation may join to snapshot edges.
const MAX_CLOSED_WEIGHTS: usize = crate::MAX_RELATION_EDGES;

/// Maximum edge weight in milli units. Relation weights above unity are never
/// admissible; the activation profile seals the same bound.
pub const MAX_EDGE_WEIGHT_MILLI: u16 = 1000;

/// Domain separator for the frozen v2 row-identity preimage.
const ROW_IDENTITY_DOMAIN: &str = "eliot.cue.row-identity.v2";

/// Prefix for frozen v2 row identities. The `v2` namespace never collides with
/// the legacy v1 `cue:` blake3 identities retained for replay.
const ROW_ID_PREFIX: &str = "cuev2:";

/// Source spelling preserved losslessly, separate from comparison material.
///
/// The canonical spelling is never a comparison policy: comparing two source
/// values always goes through an explicit [`CueComparisonKey`] derived under
/// the cited policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueSourceValue {
    /// Spelling exactly as observed, with meaningful case and separators.
    pub canonical_spelling: String,
    /// Stable reference to the source identity the spelling was observed in.
    pub source_identity_ref: String,
    /// Stable reference to the comparison policy admitted for this source.
    pub comparison_policy_ref: String,
}

impl CueSourceValue {
    /// Constructs a source value. Call [`Self::validate`] before use.
    #[must_use]
    pub const fn new(
        canonical_spelling: String,
        source_identity_ref: String,
        comparison_policy_ref: String,
    ) -> Self {
        Self {
            canonical_spelling,
            source_identity_ref,
            comparison_policy_ref,
        }
    }

    /// Validates the lossless spelling and both references without
    /// interpreting the spelling as comparison material.
    pub fn validate(&self) -> Result<(), CueContractError> {
        bounds::text(&self.canonical_spelling, "source.canonical_spelling")?;
        bounds::text(&self.source_identity_ref, "source.source_identity_ref")?;
        bounds::text(&self.comparison_policy_ref, "source.comparison_policy_ref")
    }
}

/// One explicit comparison key: scope, kind, mode, and normalized value.
///
/// Unlike the legacy single-value key, this shape never carries source
/// spelling: `normalized_value` is policy-folded lookup material only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueComparisonKey {
    /// Scope the key is comparable in.
    pub scope: String,
    /// What kind of cue the key compares.
    pub kind: CueKind,
    /// How the key is matched.
    pub mode: MatchMode,
    /// Policy-folded value used for lookup. Never source spelling.
    pub normalized_value: String,
}

impl CueComparisonKey {
    /// Constructs a comparison key. Call [`Self::validate`] before use.
    #[must_use]
    pub const fn new(
        scope: String,
        kind: CueKind,
        mode: MatchMode,
        normalized_value: String,
    ) -> Self {
        Self {
            scope,
            kind,
            mode,
            normalized_value,
        }
    }

    /// Validates scope, value, and the kind/mode admissibility rule shared
    /// with [`NormalizedCue`](crate::NormalizedCue) key validation.
    pub fn validate(&self) -> Result<(), CueContractError> {
        bounds::text(&self.scope, "comparison_key.scope")?;
        bounds::text(&self.normalized_value, "comparison_key.normalized_value")?;
        if !crate::normalization::mode_admissible(Some(self.kind), self.mode) {
            return Err(CueContractError::Foundation {
                field: "comparison_key.match_mode",
            });
        }
        Ok(())
    }
}

/// The projection dimension named by one exact omission record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum CueProjectionOmissionKind {
    /// A projection row omitted from the retained snapshot.
    Row,
    /// A relation edge omitted from the retained snapshot.
    Edge,
}

/// A bounded, owner-supplied reason for one omitted projection item.
///
/// These reasons describe projection coverage only. They do not grant support,
/// applicability, accessibility, influence, or lifecycle authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum CueProjectionOmissionReason {
    /// The exact source was unavailable for this frozen build.
    SourceUnavailable,
    /// The source revision changed before the item was retained.
    SourceRevisionChanged,
    /// The owner excluded the item under a named projection policy.
    PolicyExcluded,
    /// The item failed the bounded projection contract.
    InvalidRecord,
    /// The owner deliberately stopped at a declared projection bound.
    OwnerBound,
}

/// One exact identity and reason retained for an omitted projection item.
///
/// Counts are only a denominator. These records are the non-count closure that
/// makes a partial snapshot auditable without inventing a reason or identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueProjectionOmission {
    /// Exact row or edge identity in the owner's projection namespace.
    pub identity: String,
    /// Dimension in which the identity was omitted.
    pub kind: CueProjectionOmissionKind,
    /// Closed reason class supplied by the projection owner.
    pub reason: CueProjectionOmissionReason,
}

impl CueProjectionOmission {
    /// Constructs one exact omission record.
    #[must_use]
    pub const fn new(
        identity: String,
        kind: CueProjectionOmissionKind,
        reason: CueProjectionOmissionReason,
    ) -> Self {
        Self {
            identity,
            kind,
            reason,
        }
    }

    /// Validates the retained identity shape.
    pub fn validate(&self) -> Result<(), CueContractError> {
        bounds::text(&self.identity, "denominator.omission.identity")
    }
}

/// Frozen denominator a snapshot completeness claim is measured against.
///
/// `expected_rows`/`expected_edges` count every admitted row/edge including
/// omitted ones. `row_omissions` and `edge_omissions` retain the exact
/// identity and reason for every count; a non-zero count without its records is
/// invalid. An empty-complete snapshot carries all-zero counts and no omission
/// records. An unavailable or partial projection is never described by this
/// shape alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueProjectionDenominator {
    /// Admitted rows including omitted ones.
    pub expected_rows: usize,
    /// Admitted edges including omitted ones.
    pub expected_edges: usize,
    /// Rows held back with omission recorded.
    pub omitted_rows: usize,
    /// Edges held back with omission recorded.
    pub omitted_edges: usize,
    /// Exact row identities and reasons for all omitted rows.
    #[serde(default)]
    pub row_omissions: Vec<CueProjectionOmission>,
    /// Exact edge identities and reasons for all omitted edges.
    #[serde(default)]
    pub edge_omissions: Vec<CueProjectionOmission>,
    /// Admitted source revision the denominator was frozen at.
    pub source_revision: u64,
}

impl CueProjectionDenominator {
    /// Constructs a denominator. A non-zero omission count is intentionally
    /// incomplete until exact [`Self::with_omissions`] records are attached.
    #[must_use]
    pub const fn new(
        expected_rows: usize,
        expected_edges: usize,
        omitted_rows: usize,
        omitted_edges: usize,
        source_revision: u64,
    ) -> Self {
        Self {
            expected_rows,
            expected_edges,
            omitted_rows,
            omitted_edges,
            row_omissions: Vec::new(),
            edge_omissions: Vec::new(),
            source_revision,
        }
    }

    /// Attaches exact row and edge omission records.
    #[must_use]
    pub fn with_omissions(
        mut self,
        row_omissions: Vec<CueProjectionOmission>,
        edge_omissions: Vec<CueProjectionOmission>,
    ) -> Self {
        self.row_omissions = row_omissions;
        self.edge_omissions = edge_omissions;
        self
    }

    /// Rejects count/identity mismatches and omission records with the wrong
    /// dimension or duplicate identity.
    pub fn validate(&self) -> Result<(), CueContractError> {
        if self.source_revision == 0 {
            return Err(CueContractError::InvalidText {
                field: "denominator.source_revision",
            });
        }
        if self.expected_rows > crate::MAX_SNAPSHOT_MEMBERS {
            return Err(CueContractError::BoundExceeded {
                field: "denominator.expected_rows",
                limit: crate::MAX_SNAPSHOT_MEMBERS,
            });
        }
        if self.expected_edges > crate::MAX_RELATION_EDGES {
            return Err(CueContractError::BoundExceeded {
                field: "denominator.expected_edges",
                limit: crate::MAX_RELATION_EDGES,
            });
        }
        if self.omitted_rows > self.expected_rows {
            return Err(CueContractError::BoundExceeded {
                field: "denominator.omitted_rows",
                limit: self.expected_rows,
            });
        }
        if self.omitted_edges > self.expected_edges {
            return Err(CueContractError::BoundExceeded {
                field: "denominator.omitted_edges",
                limit: self.expected_edges,
            });
        }
        Self::validate_omissions(CueProjectionOmissionKind::Row, &self.row_omissions)?;
        Self::validate_omissions(CueProjectionOmissionKind::Edge, &self.edge_omissions)?;
        let mut identities = BTreeSet::new();
        for omission in self.row_omissions.iter().chain(self.edge_omissions.iter()) {
            if !identities.insert(&omission.identity) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "denominator.omission.identity",
                });
            }
        }
        if self.omitted_rows != self.row_omissions.len()
            || self.omitted_edges != self.edge_omissions.len()
        {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }

    fn validate_omissions(
        expected_kind: CueProjectionOmissionKind,
        omissions: &[CueProjectionOmission],
    ) -> Result<(), CueContractError> {
        let mut identities = BTreeSet::new();
        for omission in omissions {
            omission.validate()?;
            if omission.kind != expected_kind || !identities.insert(&omission.identity) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "denominator.omission.identity",
                });
            }
        }
        Ok(())
    }

    /// True only when nothing was omitted and no orphan omission record exists.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.source_revision != 0
            && self.omitted_rows == 0
            && self.omitted_edges == 0
            && self.row_omissions.is_empty()
            && self.edge_omissions.is_empty()
    }

    /// True only for "searched everything, found nothing": zero expected rows
    /// and edges with zero omissions and no omission records.
    #[must_use]
    pub fn is_empty_complete(&self) -> bool {
        self.expected_rows == 0 && self.expected_edges == 0 && self.is_complete()
    }

    /// Checks present counts against the frozen totals: present plus omitted
    /// must equal expected on both dimensions.
    pub fn validate_against(
        &self,
        present_rows: usize,
        present_edges: usize,
    ) -> Result<(), CueContractError> {
        self.validate()?;
        let held_rows = self
            .expected_rows
            .checked_sub(self.omitted_rows)
            .ok_or(CueContractError::SnapshotNotRebuildable)?;
        let held_edges = self
            .expected_edges
            .checked_sub(self.omitted_edges)
            .ok_or(CueContractError::SnapshotNotRebuildable)?;
        if present_rows != held_rows || present_edges != held_edges {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }
}

/// One snapshot member joined to the exact comparison key and source that
/// produced it.
///
/// `source_member_digest` is a domain-separated digest over the complete
/// member/key/source tuple. It makes this record independently rejectable:
/// changing the source, member, key, or frozen revision without rebuilding the
/// join cannot pass validation. The closure validator additionally joins the
/// exact source to the admitted projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ClosedSnapshotRow {
    /// The admitted member.
    pub member: SnapshotMember,
    /// The exact key the member was admitted under.
    pub key: CueComparisonKey,
    /// The exact observed source identity admitted for this row.
    pub source: SourceHandle,
    /// Frozen source revision admitted for this row.
    pub source_revision: u64,
    /// Digest binding the complete member/key/source tuple.
    pub source_member_digest: Digest,
}

impl ClosedSnapshotRow {
    /// Constructs one closed row and binds its complete producer tuple.
    pub fn new(
        member: SnapshotMember,
        key: CueComparisonKey,
        source: SourceHandle,
        source_revision: u64,
    ) -> Result<Self, CueContractError> {
        let source_member_digest = source_member_digest(&member, &key, &source, source_revision)?;
        Ok(Self {
            member,
            key,
            source,
            source_revision,
            source_member_digest,
        })
    }

    /// Constructs a closed row with the source revision frozen into it.
    pub fn new_at_revision(
        member: SnapshotMember,
        key: CueComparisonKey,
        source: SourceHandle,
        source_revision: u64,
    ) -> Result<Self, CueContractError> {
        Self::new(member, key, source, source_revision)
    }

    /// Validates the complete producer join, kind agreement, scope, source
    /// revision marker, and the source/member binding digest.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.member.validate()?;
        self.key.validate()?;
        self.source.validate()?;
        if self.key.kind != self.member.canonical.kind {
            return Err(CueContractError::Foundation {
                field: "snapshot.row.kind",
            });
        }
        if self.source.provenance.scope != self.key.scope {
            return Err(CueContractError::Foundation {
                field: "snapshot.row.source_scope",
            });
        }
        if self.source_revision == 0
            || !revision_marker_matches(
                self.source.provenance.revision.as_deref(),
                self.source_revision,
            )
        {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        let expected =
            source_member_digest(&self.member, &self.key, &self.source, self.source_revision)?;
        if self.source_member_digest != expected {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }

    /// Computes this row's frozen v2 identity.
    pub fn row_id(&self) -> Result<String, CueContractError> {
        self.member
            .row_id(&self.key.scope, self.key.mode, &self.key.normalized_value)
    }
}

#[derive(Serialize)]
struct SourceMemberPreimage<'a> {
    domain: &'a str,
    member: &'a SnapshotMember,
    key: &'a CueComparisonKey,
    source: &'a SourceHandle,
    source_revision: u64,
}

fn source_member_digest(
    member: &SnapshotMember,
    key: &CueComparisonKey,
    source: &SourceHandle,
    source_revision: u64,
) -> Result<Digest, CueContractError> {
    let bytes = eliot_contracts::canonical_json_bytes(&SourceMemberPreimage {
        domain: "eliot.cue.closed-row-source-member.v2",
        member,
        key,
        source,
        source_revision,
    })
    .map_err(|_| CueContractError::Foundation {
        field: "snapshot.row.source_member_digest",
    })?;
    Digest::new(eliot_contracts::sha256_hex(&bytes))
}

/// One activation-edge weight supplied by the numerical policy owner.
///
/// Relation edges carry no weight themselves; snapshot closure joins each edge
/// to exactly one policy-supplied weight so the bounded-weight invariant is
/// checkable at the snapshot boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SnapshotEdgeWeight {
    /// The edge this weight applies to.
    pub edge: RelationEdgeId,
    /// Policy weight in milli units. Never above unity.
    pub weight_milli: u16,
    /// Frozen source revision admitted for this edge.
    #[serde(default)]
    pub source_revision: u64,
}

impl SnapshotEdgeWeight {
    /// Constructs one edge weight. The milli bound is enforced by snapshot
    /// closure, not here, so a decoder can retain and reject corrupt input.
    #[must_use]
    pub const fn new(edge: RelationEdgeId, weight_milli: u16) -> Self {
        Self {
            edge,
            weight_milli,
            source_revision: 0,
        }
    }

    /// Constructs an edge weight with its frozen source revision.
    #[must_use]
    pub const fn new_at_revision(
        edge: RelationEdgeId,
        weight_milli: u16,
        source_revision: u64,
    ) -> Self {
        Self {
            edge,
            weight_milli,
            source_revision,
        }
    }

    /// Validates the edge reference shape.
    pub fn validate(&self) -> Result<(), CueContractError> {
        bounds::text(self.edge.as_str(), "snapshot.edge_weight.edge")
    }
}

/// Matches only an explicitly present, exact source-revision marker.
///
/// A missing marker is never equivalent to a current revision. The accepted
/// spellings are the canonical decimal form and the two bounded owner
/// prefixes used by the evidence contracts (`r` and `rev-`).
pub(crate) fn revision_marker_matches(value: Option<&str>, expected: u64) -> bool {
    if expected == 0 {
        return false;
    }
    let Some(value) = value else {
        return false;
    };
    let canonical = expected.to_string();
    value == canonical
        || value
            .strip_prefix('r')
            .is_some_and(|rest| rest == canonical)
        || value
            .strip_prefix("rev-")
            .is_some_and(|rest| rest == canonical)
}

/// Returns whether one retained source names exactly the expected revision.
pub(crate) fn source_revision_matches(source: &SourceHandle, expected: u64) -> bool {
    revision_marker_matches(source.provenance.revision.as_deref(), expected)
}

/// Explicit activation limits retained by a closed snapshot.
///
/// The graph itself is immutable, but its traversal policy is part of the
/// closure that makes a candidate safe to replay. A direct-only snapshot uses
/// [`CueSnapshotFanout::direct_only`]; a graph-bearing snapshot must retain
/// finite depth, fanout, edge, and path bounds. These are validation ceilings,
/// not scheduling or authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueSnapshotFanout {
    /// Maximum relation depth retained by this snapshot.
    pub max_depth: u8,
    /// Maximum outgoing edges considered from one node.
    pub max_fanout: u16,
    /// Maximum relation edges inspected by the bounded activation owner.
    pub max_edges: u32,
    /// Maximum edges in one derived path.
    pub max_path_len: u16,
}

impl CueSnapshotFanout {
    /// The exact direct-only closure used by a zero-edge snapshot.
    #[must_use]
    pub const fn direct_only() -> Self {
        Self {
            max_depth: 0,
            max_fanout: 0,
            max_edges: 0,
            max_path_len: 0,
        }
    }

    /// Constructs an explicit finite traversal closure.
    #[must_use]
    pub const fn bounded(
        max_depth: u8,
        max_fanout: u16,
        max_edges: u32,
        max_path_len: u16,
    ) -> Self {
        Self {
            max_depth,
            max_fanout,
            max_edges,
            max_path_len,
        }
    }

    /// Validates that every retained traversal limit is finite and internally
    /// consistent. A zero-depth closure is exactly direct-only.
    pub fn validate(&self) -> Result<(), CueContractError> {
        if self.max_depth == 0 {
            if self.max_fanout != 0 || self.max_edges != 0 || self.max_path_len != 0 {
                return Err(CueContractError::Foundation {
                    field: "snapshot.fanout.direct_only",
                });
            }
        } else if self.max_fanout == 0
            || self.max_edges == 0
            || self.max_path_len == 0
            || usize::from(self.max_depth) > crate::MAX_PATH_LEN
            || usize::from(self.max_fanout) > crate::MAX_RELATION_EDGES
            || self.max_edges > u32::try_from(crate::MAX_RELATION_EDGES).unwrap_or(u32::MAX)
            || usize::from(self.max_path_len) > crate::MAX_PATH_LEN
        {
            return Err(CueContractError::Foundation {
                field: "snapshot.fanout",
            });
        }
        Ok(())
    }

    /// Measures the exact finite graph closure and returns its observed
    /// depth, branching, edge count, and longest path. A graph-bearing
    /// snapshot uses these measured values rather than a global edge ceiling.
    pub fn from_graph(
        members: &[SnapshotMember],
        edges: &[crate::RelationEdge],
    ) -> Result<Self, CueContractError> {
        if edges.is_empty() {
            return Ok(Self::direct_only());
        }
        let measured = Self::measure_graph(members, edges)?;
        let value = Self {
            max_depth: u8::try_from(measured.depth).map_err(|_| {
                CueContractError::BoundExceeded {
                    field: "snapshot.fanout.max_depth",
                    limit: crate::MAX_PATH_LEN,
                }
            })?,
            max_fanout: u16::try_from(measured.fanout).map_err(|_| {
                CueContractError::BoundExceeded {
                    field: "snapshot.fanout.max_fanout",
                    limit: crate::MAX_RELATION_EDGES,
                }
            })?,
            max_edges: u32::try_from(measured.edge_count).map_err(|_| {
                CueContractError::BoundExceeded {
                    field: "snapshot.fanout.max_edges",
                    limit: crate::MAX_RELATION_EDGES,
                }
            })?,
            max_path_len: u16::try_from(measured.depth).map_err(|_| {
                CueContractError::BoundExceeded {
                    field: "snapshot.fanout.max_path_len",
                    limit: crate::MAX_PATH_LEN,
                }
            })?,
        };
        value.validate_for_graph(members, edges)?;
        Ok(value)
    }

    /// Validates the exact graph closure represented by this fanout record.
    /// It rejects cycles, unreachable edges/nodes, and a record whose measured
    /// values differ from the retained values.
    pub fn validate_for_graph(
        &self,
        members: &[SnapshotMember],
        edges: &[crate::RelationEdge],
    ) -> Result<(), CueContractError> {
        self.validate()?;
        if edges.is_empty() {
            return if *self == Self::direct_only() {
                Ok(())
            } else {
                Err(CueContractError::Foundation {
                    field: "snapshot.fanout.direct_only",
                })
            };
        }
        let measured = Self::measure_graph(members, edges)?;
        if usize::from(self.max_depth) != measured.depth
            || usize::from(self.max_fanout) != measured.fanout
            || usize::try_from(self.max_edges).ok() != Some(measured.edge_count)
            || usize::from(self.max_path_len) != measured.depth
        {
            return Err(CueContractError::Foundation {
                field: "snapshot.fanout.observed",
            });
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "graph closure validation keeps endpoint, cycle, reachability, and measurement checks together"
    )]
    fn measure_graph(
        members: &[SnapshotMember],
        edges: &[crate::RelationEdge],
    ) -> Result<MeasuredFanout, CueContractError> {
        for member in members {
            member.validate()?;
        }
        for edge in edges {
            edge.validate()?;
        }
        let nodes: BTreeSet<TargetHandle> =
            members.iter().map(|member| member.target.clone()).collect();
        let mut outgoing: BTreeMap<TargetHandle, Vec<TargetHandle>> = BTreeMap::new();
        let mut indegree: BTreeMap<TargetHandle, usize> =
            nodes.iter().cloned().map(|node| (node, 0)).collect();
        let mut edge_ids = BTreeSet::new();
        for edge in edges {
            if !edge_ids.insert(edge.relation_edge_id.clone()) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "snapshot.graph.edge_id",
                });
            }
            if !nodes.contains(&edge.from) || !nodes.contains(&edge.to) {
                return Err(CueContractError::Foundation {
                    field: "snapshot.graph.endpoint",
                });
            }
            outgoing
                .entry(edge.from.clone())
                .or_default()
                .push(edge.to.clone());
            *indegree
                .get_mut(&edge.to)
                .ok_or(CueContractError::Foundation {
                    field: "snapshot.graph.endpoint",
                })? += 1;
        }
        let roots: Vec<TargetHandle> = indegree
            .iter()
            .filter_map(|(node, degree)| (*degree == 0).then_some(node.clone()))
            .collect();
        let mut queue: VecDeque<TargetHandle> = roots.iter().cloned().collect();
        if queue.is_empty() {
            return Err(CueContractError::Foundation {
                field: "snapshot.graph.cycle",
            });
        }
        let mut depth: BTreeMap<TargetHandle, usize> =
            indegree.keys().cloned().map(|node| (node, 0)).collect();
        let mut processed = 0usize;
        let mut max_depth = 0usize;
        while let Some(node) = queue.pop_front() {
            processed += 1;
            let node_depth = depth.get(&node).copied().unwrap_or(0);
            max_depth = max_depth.max(node_depth);
            if let Some(targets) = outgoing.get(&node) {
                for target in targets {
                    let next_depth = node_depth.saturating_add(1);
                    let entry = depth.entry(target.clone()).or_insert(0);
                    *entry = (*entry).max(next_depth);
                    let degree = indegree
                        .get_mut(target)
                        .ok_or(CueContractError::Foundation {
                            field: "snapshot.graph.endpoint",
                        })?;
                    *degree = degree.saturating_sub(1);
                    if *degree == 0 {
                        queue.push_back(target.clone());
                    }
                }
            }
        }
        if processed != nodes.len() {
            return Err(CueContractError::Foundation {
                field: "snapshot.graph.cycle",
            });
        }
        let mut reachable_nodes = BTreeSet::new();
        let mut reach_queue: VecDeque<TargetHandle> = roots.into_iter().collect();
        while let Some(node) = reach_queue.pop_front() {
            if !reachable_nodes.insert(node.clone()) {
                continue;
            }
            if let Some(targets) = outgoing.get(&node) {
                reach_queue.extend(targets.iter().cloned());
            }
        }
        let reachable_edges = reachable_nodes
            .iter()
            .filter_map(|node| outgoing.get(node))
            .map(Vec::len)
            .sum::<usize>();
        if reachable_nodes.len() != nodes.len() || reachable_edges != edges.len() {
            return Err(CueContractError::Foundation {
                field: "snapshot.graph.reachability",
            });
        }
        let max_fanout = outgoing.values().map(Vec::len).max().unwrap_or(0);
        if max_depth == 0 || max_fanout == 0 {
            return Err(CueContractError::Foundation {
                field: "snapshot.graph.observed",
            });
        }
        if max_depth > crate::MAX_PATH_LEN || max_fanout > crate::MAX_RELATION_EDGES {
            return Err(CueContractError::BoundExceeded {
                field: "snapshot.graph.bound",
                limit: crate::MAX_PATH_LEN,
            });
        }
        Ok(MeasuredFanout {
            depth: max_depth,
            fanout: max_fanout,
            edge_count: edges.len(),
        })
    }
}

struct MeasuredFanout {
    depth: usize,
    fanout: usize,
    edge_count: usize,
}

/// All state needed to validate one published cue snapshot without an external
/// closure argument.
///
/// The fields are deliberately a closed set. An open compatibility candidate
/// may exist for package fixtures, but only a candidate carrying this closure
/// can be presented as a published/closed snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueSnapshotClosure {
    /// Frozen row/edge denominator and omission counts.
    pub denominator: CueProjectionDenominator,
    /// Exact row-to-comparison-key joins.
    pub rows: Vec<ClosedSnapshotRow>,
    /// Exact typed relation edges and their endpoints.
    pub relation_edges: Vec<crate::RelationEdge>,
    /// Exact policy weight for every retained edge.
    pub edge_weights: Vec<SnapshotEdgeWeight>,
    /// Explicit activation/fanout closure.
    pub fanout: CueSnapshotFanout,
}

impl CueSnapshotClosure {
    /// Constructs one immutable closure record.
    #[must_use]
    pub const fn new(
        denominator: CueProjectionDenominator,
        rows: Vec<ClosedSnapshotRow>,
        relation_edges: Vec<crate::RelationEdge>,
        edge_weights: Vec<SnapshotEdgeWeight>,
        fanout: CueSnapshotFanout,
    ) -> Self {
        Self {
            denominator,
            rows,
            relation_edges,
            edge_weights,
            fanout,
        }
    }

    /// Validates the closure fields that do not depend on the member set.
    pub fn validate_shape(&self) -> Result<(), CueContractError> {
        self.denominator.validate()?;
        self.fanout.validate()?;
        bounds::collection(&self.rows, MAX_CLOSED_ROWS, "snapshot.rows")?;
        bounds::collection(
            &self.relation_edges,
            MAX_CLOSED_WEIGHTS,
            "snapshot.relation_edges",
        )?;
        bounds::collection(
            &self.edge_weights,
            MAX_CLOSED_WEIGHTS,
            "snapshot.edge_weights",
        )?;
        for row in &self.rows {
            row.validate()?;
        }
        for edge in &self.relation_edges {
            edge.validate()?;
        }
        for weight in &self.edge_weights {
            weight.validate()?;
        }
        if self.denominator.omitted_rows != self.denominator.row_omissions.len()
            || self.denominator.omitted_edges != self.denominator.edge_omissions.len()
        {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        if self.relation_edges.len() != self.edge_weights.len() {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        if !self.relation_edges.is_empty() && self.fanout.max_depth == 0 {
            return Err(CueContractError::Foundation {
                field: "snapshot.fanout.edge",
            });
        }
        Ok(())
    }
}

/// What a v1 migration did. Never an admission: replay preserves old
/// bytes/identity, conversion adds a v2 identity beside the preserved legacy
/// one, and rejection names a bounded reason while the caller keeps v1 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ConversionDisposition {
    /// Old v1 bytes and identity retained for replay; no v2 identity issued.
    V1ReplayPreserved {
        /// Legacy row identity kept byte-identical.
        legacy_row_id: String,
    },
    /// V2 row identity issued; the legacy identity is preserved alongside it.
    V2Converted {
        /// Legacy row identity kept byte-identical.
        legacy_row_id: String,
        /// Frozen v2 row identity from [`cue_row_id`].
        row_id: String,
    },
    /// Conversion refused; the caller retains v1 bytes under this reason.
    V2Rejected {
        /// Legacy row identity the refusal applies to.
        legacy_row_id: String,
        /// Stable bounded reason class.
        reason: String,
    },
}

impl ConversionDisposition {
    /// Validates the retained identities and the bounded refusal reason.
    pub fn validate(&self) -> Result<(), CueContractError> {
        match self {
            Self::V1ReplayPreserved { legacy_row_id }
            | Self::V2Converted {
                legacy_row_id,
                row_id: _,
            } => {
                bounds::text(legacy_row_id, "conversion.legacy_row_id")?;
                if let Self::V2Converted { row_id, .. } = self {
                    bounds::text(row_id, "conversion.row_id")?;
                    let Some(digest) = row_id.strip_prefix(ROW_ID_PREFIX) else {
                        return Err(CueContractError::Foundation {
                            field: "conversion.row_id.namespace",
                        });
                    };
                    Digest::new(digest.to_owned()).map_err(|_| CueContractError::Foundation {
                        field: "conversion.row_id.digest",
                    })?;
                }
                Ok(())
            }
            Self::V2Rejected {
                legacy_row_id,
                reason,
            } => {
                bounds::text(legacy_row_id, "conversion.legacy_row_id")?;
                bounds::text(reason, "conversion.reason")?;
                if !matches!(
                    reason.as_str(),
                    "missing_fresh_observation"
                        | "fresh_observation_mismatch"
                        | "missing_normalized_key"
                        | "unsupported_legacy_identity"
                ) {
                    return Err(CueContractError::Foundation {
                        field: "conversion.reason",
                    });
                }
                Ok(())
            }
        }
    }

    /// True only for the replay path, which issues no new identity.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        matches!(self, Self::V1ReplayPreserved { .. })
    }

    /// True only when a fresh owner observation produced a v2 identity.
    #[must_use]
    pub const fn is_converted(&self) -> bool {
        matches!(self, Self::V2Converted { .. })
    }

    /// True only when conversion was explicitly refused.
    #[must_use]
    pub const fn is_rejected(&self) -> bool {
        matches!(self, Self::V2Rejected { .. })
    }

    /// Returns the v2 identity only for a converted disposition.
    #[must_use]
    pub fn v2_row_id(&self) -> Option<&str> {
        match self {
            Self::V2Converted { row_id, .. } => Some(row_id),
            Self::V1ReplayPreserved { .. } | Self::V2Rejected { .. } => None,
        }
    }

    /// Returns the preserved legacy identity carried by every disposition.
    #[must_use]
    pub fn legacy_row_id(&self) -> &str {
        match self {
            Self::V1ReplayPreserved { legacy_row_id }
            | Self::V2Converted { legacy_row_id, .. }
            | Self::V2Rejected { legacy_row_id, .. } => legacy_row_id,
        }
    }
}

#[derive(Serialize)]
struct RowIdentityPreimage<'a> {
    domain: &'a str,
    identity_revision: &'a str,
    scope: &'a str,
    kind: CueKind,
    mode: MatchMode,
    normalized_value: &'a str,
    target: &'a str,
}

/// Computes the frozen v2 row identity for one semantic key.
///
/// Binds scope, kind, mode, normalized comparison key, target identity, and
/// the identity-contract revision ([`CONTRACT_REVISION`]) under a
/// domain-separated canonical-JSON/sha256 preimage. The output namespace
/// (`cuev2:`) never collides with legacy v1 `cue:` identities.
///
/// # Errors
/// Rejects blank scopes or values, oversized text, and kind/mode combinations
/// the cue vocabulary does not admit.
pub fn cue_row_id(
    scope: &str,
    kind: CueKind,
    mode: MatchMode,
    normalized_value: &str,
    target: &TargetHandle,
) -> Result<String, CueContractError> {
    bounds::text(scope, "row_identity.scope")?;
    bounds::text(normalized_value, "row_identity.normalized_value")?;
    bounds::text(target.as_str(), "row_identity.target")?;
    if !crate::normalization::mode_admissible(Some(kind), mode) {
        return Err(CueContractError::Foundation {
            field: "row_identity.match_mode",
        });
    }
    let preimage = RowIdentityPreimage {
        domain: ROW_IDENTITY_DOMAIN,
        identity_revision: CONTRACT_REVISION,
        scope,
        kind,
        mode,
        normalized_value,
        target: target.as_str(),
    };
    let bytes = eliot_contracts::canonical_json_bytes(&preimage).map_err(|_| {
        CueContractError::Foundation {
            field: "row_identity.canonical_payload",
        }
    })?;
    Ok(format!(
        "{ROW_ID_PREFIX}{}",
        eliot_contracts::sha256_hex(&bytes)
    ))
}

/// Closed-validation joins shared by [`CueSnapshot`](crate::CueSnapshot).
pub(crate) fn validate_closed_rows(
    members: &[SnapshotMember],
    rows: &[ClosedSnapshotRow],
) -> Result<Vec<String>, CueContractError> {
    bounds::collection(rows, MAX_CLOSED_ROWS, "snapshot.rows")?;
    if rows.len() != members.len() {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    let mut coverage = std::collections::BTreeMap::new();
    for member in members {
        let key = (
            member.canonical.canonical_cue_id.clone(),
            member.target.clone(),
        );
        if coverage.insert(key, member).is_some() {
            return Err(CueContractError::DuplicateIdentity {
                field: "snapshot.members",
            });
        }
    }
    let mut row_ids = Vec::with_capacity(rows.len());
    let mut seen_row_ids = std::collections::BTreeSet::new();
    let mut seen_semantic = std::collections::BTreeSet::new();
    for row in rows {
        row.validate()?;
        let key = (
            row.member.canonical.canonical_cue_id.clone(),
            row.member.target.clone(),
        );
        let Some(expected_member) = coverage.remove(&key) else {
            return Err(CueContractError::SnapshotNotRebuildable);
        };
        // The key alone is not a row join. The complete canonical member and
        // target must be byte-for-byte equal to the snapshot member, otherwise
        // a caller could retain one member while validating a different row.
        if &row.member != expected_member {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        let row_id = row.row_id()?;
        if !seen_row_ids.insert(row_id.clone()) {
            return Err(CueContractError::DuplicateIdentity {
                field: "snapshot.row_id",
            });
        }
        let semantic = (
            row.member.canonical.kind,
            row.member.canonical.canonical_value.clone(),
            row.member.target.clone(),
        );
        if !seen_semantic.insert(semantic) {
            return Err(CueContractError::DuplicateIdentity {
                field: "snapshot.semantic_binding",
            });
        }
        row_ids.push(row_id);
    }
    if !coverage.is_empty() {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(row_ids)
}

/// Closed row/source join with the source revision frozen into every retained
/// row. The source set is part of the proof, rather than an external hint.
pub(crate) fn validate_closed_rows_at_revision(
    members: &[SnapshotMember],
    rows: &[ClosedSnapshotRow],
    sources: &[SourceHandle],
    source_revision: u64,
) -> Result<Vec<String>, CueContractError> {
    let ids = validate_closed_rows(members, rows)?;
    if source_revision == 0
        || sources
            .iter()
            .any(|source| !source_revision_matches(source, source_revision))
        || rows.iter().any(|row| {
            row.source_revision != source_revision
                || !sources.iter().any(|source| source == &row.source)
                || !source_revision_matches(&row.source, source_revision)
        })
    {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    if sources
        .iter()
        .any(|source| !rows.iter().any(|row| row.source == *source))
    {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(ids)
}

/// Closed-validation weight join shared by [`CueSnapshot`](crate::CueSnapshot).
pub(crate) fn validate_closed_weights(
    edges: &[crate::RelationEdge],
    weights: &[SnapshotEdgeWeight],
) -> Result<(), CueContractError> {
    bounds::collection(weights, MAX_CLOSED_WEIGHTS, "snapshot.edge_weights")?;
    if weights.len() != edges.len() {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    let mut expected = std::collections::BTreeSet::new();
    for edge in edges {
        edge.validate()?;
        if !expected.insert(edge.relation_edge_id.clone()) {
            return Err(CueContractError::DuplicateIdentity {
                field: "snapshot.edges",
            });
        }
    }
    for weight in weights {
        weight.validate()?;
        if !expected.remove(&weight.edge) {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        if weight.weight_milli > MAX_EDGE_WEIGHT_MILLI {
            return Err(CueContractError::BoundExceeded {
                field: "snapshot.edge.weight",
                limit: usize::from(MAX_EDGE_WEIGHT_MILLI),
            });
        }
    }
    if !expected.is_empty() {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(())
}

/// Closed weight join with the source revision frozen into every retained edge.
pub(crate) fn validate_closed_weights_at_revision(
    edges: &[crate::RelationEdge],
    weights: &[SnapshotEdgeWeight],
    source_revision: u64,
) -> Result<(), CueContractError> {
    validate_closed_weights(edges, weights)?;
    if source_revision == 0
        || weights
            .iter()
            .any(|weight| weight.source_revision != source_revision)
    {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(())
}
