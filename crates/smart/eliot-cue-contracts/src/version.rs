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

use crate::{
    CONTRACT_REVISION, CueContractError, RelationEdgeId, SnapshotMember, SourceHandle,
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

/// Frozen denominator a snapshot completeness claim is measured against.
///
/// `expected_rows`/`expected_edges` count every admitted row/edge including
/// omitted ones; `omitted_*` counts the rows/edges the snapshot holds back
/// with their omission recorded elsewhere. An empty-complete snapshot carries
/// all-zero counts; an unavailable or partial projection is never described by
/// this shape alone — partial validation succeeds but classifies differently
/// (see [`Self::is_empty_complete`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// Admitted source revision the denominator was frozen at.
    pub source_revision: u64,
}

impl CueProjectionDenominator {
    /// Constructs a denominator. Call [`Self::validate`] before use.
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
            source_revision,
        }
    }

    /// Rejects omitted counts that exceed the totals they are measured against.
    pub const fn validate(&self) -> Result<(), CueContractError> {
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
        Ok(())
    }

    /// True only when nothing was omitted.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.omitted_rows == 0 && self.omitted_edges == 0
    }

    /// True only for "searched everything, found nothing": zero expected rows
    /// and edges with zero omissions. A partial or unavailable projection never
    /// satisfies this even when its present counts are zero.
    #[must_use]
    pub const fn is_empty_complete(&self) -> bool {
        self.expected_rows == 0
            && self.expected_edges == 0
            && self.omitted_rows == 0
            && self.omitted_edges == 0
    }

    /// Checks present counts against the frozen totals: present plus omitted
    /// must equal expected on both dimensions.
    pub const fn validate_against(
        &self,
        present_rows: usize,
        present_edges: usize,
    ) -> Result<(), CueContractError> {
        if let Err(error) = self.validate() {
            return Err(error);
        }
        let Some(held_rows) = self.expected_rows.checked_sub(self.omitted_rows) else {
            return Err(CueContractError::SnapshotNotRebuildable);
        };
        let Some(held_edges) = self.expected_edges.checked_sub(self.omitted_edges) else {
            return Err(CueContractError::SnapshotNotRebuildable);
        };
        if present_rows != held_rows || present_edges != held_edges {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }
}

/// One snapshot member joined to the exact comparison key it was admitted under.
///
/// The join is what makes row identity computable: the member carries kind and
/// target, the key carries scope, mode, and normalized value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ClosedSnapshotRow {
    /// The admitted member.
    pub member: SnapshotMember,
    /// The exact key the member was admitted under.
    pub key: CueComparisonKey,
    /// The exact observed source identity admitted for this row.
    ///
    /// A closed row is not complete without this join. The source handle is
    /// retained alongside the member so validation can prove that the row,
    /// projection, and source denominator all refer to the same observation.
    pub source: SourceHandle,
    /// Frozen source revision admitted for this row.
    pub source_revision: u64,
}

impl ClosedSnapshotRow {
    /// Constructs one closed row. Call [`Self::validate`] before use.
    #[must_use]
    pub const fn new(
        member: SnapshotMember,
        key: CueComparisonKey,
        source: SourceHandle,
        source_revision: u64,
    ) -> Self {
        Self {
            member,
            key,
            source,
            source_revision,
        }
    }

    /// Constructs a closed row with the source revision frozen into it.
    #[must_use]
    pub const fn new_at_revision(
        member: SnapshotMember,
        key: CueComparisonKey,
        source: SourceHandle,
        source_revision: u64,
    ) -> Self {
        Self::new(member, key, source, source_revision)
    }

    /// Validates the member, comparison key, source handle, kind agreement,
    /// and the source revision marker carried by the source itself.
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
        Ok(())
    }

    /// Computes this row's frozen v2 identity.
    pub fn row_id(&self) -> Result<String, CueContractError> {
        self.member
            .row_id(&self.key.scope, self.key.mode, &self.key.normalized_value)
    }
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
}

/// All state needed to validate one published cue snapshot without an external
/// closure argument.
///
/// The fields are deliberately a closed set. A candidate may still be built by
/// the legacy open constructor for package fixtures, but a candidate that
/// carries this closure is self-validating and is the only shape accepted by
/// the current Governor production path.
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
                    if !row_id.starts_with(ROW_ID_PREFIX) {
                        return Err(CueContractError::Foundation {
                            field: "conversion.row_id.namespace",
                        });
                    }
                }
                Ok(())
            }
            Self::V2Rejected {
                legacy_row_id,
                reason,
            } => {
                bounds::text(legacy_row_id, "conversion.legacy_row_id")?;
                bounds::text(reason, "conversion.reason")
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
