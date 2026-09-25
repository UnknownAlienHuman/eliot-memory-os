//! Immutable, rebuildable snapshot membership.
//!
//! `I12.7` requires a snapshot to be rebuildable. That is only checkable if the
//! snapshot carries the inputs it was built from, so `RebuildIdentity` is part
//! of the record rather than something a caller is trusted to remember.

use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{
    CanonicalCueIdentity, ClosedSnapshotRow, CueContractError, CueProjectionDenominator,
    CueSnapshotClosure, Digest, MAX_SNAPSHOT_MEMBERS, MatchMode, NormalizationProfile,
    SnapshotEdgeWeight, SnapshotId, SourceHandle, TargetHandle, bounds,
};

#[derive(Serialize)]
struct SnapshotPreimage<'a> {
    schema_revision: &'a str,
    snapshot_id: &'a SnapshotId,
    state_fence: &'a StateFence,
    #[serde(skip_serializing_if = "is_zero")]
    source_revision: u64,
    normalization_profile: &'a NormalizationProfile,
    source_denominator: Vec<&'a SourceHandle>,
    members: Vec<&'a SnapshotMember>,
    #[serde(skip_serializing_if = "Option::is_none")]
    closure: Option<&'a CueSnapshotClosure>,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde passes field references to skip predicates"
)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// One admitted cue-to-target pair inside a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SnapshotMember {
    /// The canonical cue.
    pub canonical: CanonicalCueIdentity,
    /// The bound target.
    pub target: TargetHandle,
}

impl SnapshotMember {
    /// Constructs one snapshot membership.
    #[must_use]
    pub const fn new(canonical: CanonicalCueIdentity, target: TargetHandle) -> Self {
        Self { canonical, target }
    }

    /// Validates the nested canonical identity and target handle.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.canonical.validate()?;
        bounds::text(self.target.as_str(), "member.target")
    }

    /// Computes the frozen v2 row identity for this member under one explicit
    /// comparison key.
    ///
    /// Binds scope (caller-supplied), kind (this member's canonical kind),
    /// mode and normalized value (caller-supplied key material), target (this
    /// member's target), and the identity-contract revision
    /// ([`CONTRACT_REVISION`](crate::CONTRACT_REVISION)) through
    /// [`cue_row_id`](crate::cue_row_id). Same text in different kinds or
    /// modes therefore yields distinct identities.
    pub fn row_id(
        &self,
        scope: &str,
        mode: MatchMode,
        normalized_value: &str,
    ) -> Result<String, CueContractError> {
        crate::cue_row_id(
            scope,
            self.canonical.kind,
            mode,
            normalized_value,
            &self.target,
        )
    }
}

/// Everything needed to rebuild a snapshot and check that it matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RebuildIdentity {
    /// The normalization profile every member was folded under.
    pub normalization_profile: NormalizationProfile,
    /// The exact sources the snapshot was built from. This is the denominator:
    /// a coverage claim about the snapshot is measured against it.
    pub source_denominator: Vec<SourceHandle>,
    /// Digest over the profile, the denominator and the member set.
    pub digest: Digest,
}

impl RebuildIdentity {
    /// Constructs a rebuild identity.
    #[must_use]
    pub const fn new(
        normalization_profile: NormalizationProfile,
        source_denominator: Vec<SourceHandle>,
        digest: Digest,
    ) -> Self {
        Self {
            normalization_profile,
            source_denominator,
            digest,
        }
    }
}

/// An immutable set of admitted cue-to-target memberships.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueSnapshot {
    /// Schema revision this record was written against.
    pub schema_revision: String,
    /// Identity of this snapshot.
    pub snapshot_id: SnapshotId,
    /// The admitted memberships.
    pub members: Vec<SnapshotMember>,
    /// The inputs that make the snapshot reconstructible.
    pub rebuild: RebuildIdentity,
    /// The causal snapshot this was built against.
    pub state_fence: StateFence,
    /// Source revision frozen into a closed snapshot. Open legacy fixtures use
    /// zero and are not complete publication claims.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_revision: u64,
    /// Retained closed row/edge/denominator/fanout state. `None` is reserved
    /// for the explicitly open compatibility builder and is not a published
    /// snapshot representation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure: Option<CueSnapshotClosure>,
}

impl CueSnapshot {
    /// Constructs a snapshot. Call [`Self::validate`] before use.
    #[must_use]
    pub const fn new(
        schema_revision: String,
        snapshot_id: SnapshotId,
        members: Vec<SnapshotMember>,
        rebuild: RebuildIdentity,
        state_fence: StateFence,
    ) -> Self {
        Self {
            schema_revision,
            snapshot_id,
            members,
            rebuild,
            state_fence,
            source_revision: 0,
            closure: None,
        }
    }

    /// Attaches an immutable closure to a snapshot and freezes its source
    /// revision from the denominator. The caller must recompute
    /// [`Self::rebuild`]'s digest after this operation.
    #[must_use]
    pub fn with_closure(mut self, closure: CueSnapshotClosure) -> Self {
        self.source_revision = closure.denominator.source_revision;
        self.closure = Some(closure);
        self
    }

    /// Returns whether this snapshot carries a self-contained closed record.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closure.is_some()
    }

    /// Returns the retained closure, if this is a closed snapshot.
    #[must_use]
    pub const fn retained_closure(&self) -> Option<&CueSnapshotClosure> {
        self.closure.as_ref()
    }

    /// Returns the versioned canonical JSON preimage, excluding `digest`.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, CueContractError> {
        self.validate_shape()?;
        let mut sources: Vec<_> = self.rebuild.source_denominator.iter().collect();
        sources.sort_by(|left, right| {
            left.target
                .cmp(&right.target)
                .then(left.digest.cmp(&right.digest))
        });
        let mut members: Vec<_> = self.members.iter().collect();
        members.sort_by(|left, right| {
            left.canonical
                .canonical_cue_id
                .cmp(&right.canonical.canonical_cue_id)
                .then(left.target.cmp(&right.target))
        });
        let closure = self.closure.as_ref().map(|value| {
            let mut value = value.clone();
            value.rows.sort_by(|left, right| {
                left.member
                    .canonical
                    .canonical_cue_id
                    .cmp(&right.member.canonical.canonical_cue_id)
                    .then(left.member.target.cmp(&right.member.target))
            });
            value
                .relation_edges
                .sort_by(|left, right| left.relation_edge_id.cmp(&right.relation_edge_id));
            value
                .edge_weights
                .sort_by(|left, right| left.edge.cmp(&right.edge));
            value
                .denominator
                .row_omissions
                .sort_by(|left, right| left.identity.cmp(&right.identity));
            value
                .denominator
                .edge_omissions
                .sort_by(|left, right| left.identity.cmp(&right.identity));
            value
        });
        let preimage = SnapshotPreimage {
            schema_revision: &self.schema_revision,
            snapshot_id: &self.snapshot_id,
            state_fence: &self.state_fence,
            source_revision: self.source_revision,
            normalization_profile: &self.rebuild.normalization_profile,
            source_denominator: sources,
            members,
            closure: closure.as_ref(),
        };
        let bytes = eliot_contracts::canonical_json_bytes(&preimage).map_err(|_| {
            CueContractError::Foundation {
                field: "snapshot.canonical_payload",
            }
        })?;
        let mut total = 0;
        bounds::bytes(&mut total, bytes.len(), "snapshot.canonical_payload")?;
        Ok(bytes)
    }

    /// Computes this snapshot's canonical rebuild digest.
    pub fn canonical_digest(&self) -> Result<Digest, CueContractError> {
        let bytes = self.canonical_payload_bytes()?;
        Digest::new(eliot_contracts::sha256_hex(&bytes))
    }

    /// Compatibility name for callers that need the canonical digest input.
    pub fn recompute_digest_input(&self) -> Result<Vec<u8>, CueContractError> {
        self.canonical_payload_bytes()
    }

    /// Checks closed-snapshot invariants using the closure retained on this
    /// record. No denominator, row, endpoint, weight, or fanout argument is
    /// needed: a closed snapshot is self-validating.
    pub fn validate_self_closed(&self) -> Result<(), CueContractError> {
        self.validate_rebuild()?;
        let closure = self
            .closure
            .as_ref()
            .ok_or(CueContractError::SnapshotNotRebuildable)?;
        closure.validate_shape()?;
        if self.source_revision == 0 || self.source_revision != closure.denominator.source_revision
        {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        closure
            .denominator
            .validate_against(self.members.len(), closure.relation_edges.len())?;
        crate::version::validate_closed_rows_at_revision(
            &self.members,
            &closure.rows,
            &self.rebuild.source_denominator,
            self.source_revision,
        )?;
        validate_uniform_scope(
            &closure.rows,
            &self.rebuild.source_denominator,
            &closure.relation_edges,
        )?;
        validate_closed_endpoints(&self.members, &closure.relation_edges)?;
        crate::version::CueSnapshotFanout::validate_for_graph(
            &closure.fanout,
            &self.members,
            &closure.relation_edges,
        )?;
        validate_omission_identities(&closure.denominator, &closure.rows, &closure.relation_edges)?;
        crate::version::validate_closed_weights_at_revision(
            &closure.relation_edges,
            &closure.edge_weights,
            self.source_revision,
        )?;
        for source in &self.rebuild.source_denominator {
            if !crate::version::source_revision_matches(source, self.source_revision) {
                return Err(CueContractError::Foundation {
                    field: "snapshot.source.revision",
                });
            }
        }
        for edge in &closure.relation_edges {
            if !crate::version::revision_marker_matches(
                edge.evidence.provenance.revision.as_deref(),
                self.source_revision,
            ) {
                return Err(CueContractError::Foundation {
                    field: "snapshot.edge.revision",
                });
            }
        }
        Ok(())
    }

    /// Validates only a self-validating published snapshot. An open
    /// compatibility record is rejected rather than presented as closed.
    pub fn validate_published(&self) -> Result<(), CueContractError> {
        if !self.is_closed() {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        self.validate_self_closed()
    }

    /// Checks closed-snapshot invariants beyond rebuildability.
    ///
    /// For a closed record this compatibility seam verifies that the supplied
    /// values are exactly the retained closure and then delegates to
    /// [`Self::validate_self_closed`]. For an open compatibility fixture it
    /// preserves the explicit external validation behavior; publication paths
    /// use the self-contained method above.
    pub fn validate_closed(
        &self,
        rows: &[ClosedSnapshotRow],
        denominator: &CueProjectionDenominator,
        edges: &[crate::RelationEdge],
        weights: &[SnapshotEdgeWeight],
    ) -> Result<(), CueContractError> {
        if let Some(closure) = &self.closure {
            if rows != closure.rows.as_slice()
                || *denominator != closure.denominator
                || edges != closure.relation_edges.as_slice()
                || weights != closure.edge_weights.as_slice()
            {
                return Err(CueContractError::SnapshotNotRebuildable);
            }
            return self.validate_self_closed();
        }
        self.validate_rebuild()?;
        denominator.validate()?;
        denominator.validate_against(self.members.len(), edges.len())?;
        crate::version::validate_closed_rows_at_revision(
            &self.members,
            rows,
            &self.rebuild.source_denominator,
            denominator.source_revision,
        )?;
        validate_uniform_scope(rows, &self.rebuild.source_denominator, edges)?;
        validate_closed_endpoints(&self.members, edges)?;
        crate::version::CueSnapshotFanout::from_graph(&self.members, edges)?;
        crate::version::validate_closed_weights(edges, weights)?;
        validate_omission_identities(denominator, rows, edges)?;
        Ok(())
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects a member set past its bound, a duplicate membership, a malformed
    /// retained closure, and a rebuild record whose digest does not match its
    /// own inputs. A record carrying a closure is always checked as a closed
    /// snapshot; an open compatibility fixture remains explicitly open.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.validate_rebuild()?;
        if self.closure.is_some() {
            self.validate_self_closed()?;
        }
        Ok(())
    }

    fn validate_rebuild(&self) -> Result<(), CueContractError> {
        self.validate_shape()?;
        if self.rebuild.digest != self.canonical_digest()? {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), CueContractError> {
        bounds::collection(
            &self.rebuild.source_denominator,
            MAX_SNAPSHOT_MEMBERS,
            "source_denominator",
        )?;
        bounds::collection(&self.members, MAX_SNAPSHOT_MEMBERS, "members")?;
        self.validate_payload_budget()?;
        if !crate::is_supported_schema_revision(&self.schema_revision) {
            return Err(CueContractError::InvalidText {
                field: "schema_revision",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "snapshot.state_fence",
            })?;
        self.rebuild.normalization_profile.validate()?;
        if self.source_revision != 0 && self.closure.is_none() {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        if let Some(closure) = &self.closure {
            closure.validate_shape()?;
            if self.source_revision == 0
                || self.source_revision != closure.denominator.source_revision
            {
                return Err(CueContractError::SnapshotNotRebuildable);
            }
        }
        for source in &self.rebuild.source_denominator {
            source.validate()?;
        }
        let mut seen = BTreeSet::new();
        let mut source_seen = BTreeSet::new();
        for source in &self.rebuild.source_denominator {
            if !source_seen.insert((source.target.clone(), source.digest.clone())) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "source_denominator",
                });
            }
        }
        for member in &self.members {
            member.validate()?;
            let key = (
                member.canonical.canonical_cue_id.clone(),
                member.target.clone(),
            );
            if !seen.insert(key) {
                return Err(CueContractError::DuplicateIdentity { field: "members" });
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the byte budget enumerates each retained snapshot leaf before canonicalization"
    )]
    fn validate_payload_budget(&self) -> Result<(), CueContractError> {
        let mut measured_bytes = 0;
        bounds::bytes(
            &mut measured_bytes,
            self.schema_revision.len(),
            "snapshot.schema_revision",
        )?;
        bounds::bytes(
            &mut measured_bytes,
            self.snapshot_id.as_str().len(),
            "snapshot.snapshot_id",
        )?;
        bounds::bytes(&mut measured_bytes, 8, "snapshot.source_revision")?;
        bounds::bytes(
            &mut measured_bytes,
            self.rebuild.normalization_profile.profile_id.len(),
            "snapshot.profile_id",
        )?;
        bounds::bytes(
            &mut measured_bytes,
            self.rebuild.normalization_profile.digest.as_str().len(),
            "snapshot.profile_digest",
        )?;
        bounds::bytes(
            &mut measured_bytes,
            self.rebuild.digest.as_str().len(),
            "snapshot.rebuild_digest",
        )?;
        bounds::bytes(
            &mut measured_bytes,
            self.rebuild.source_denominator.len(),
            "snapshot.source_denominator",
        )?;
        bounds::bytes(&mut measured_bytes, self.members.len(), "snapshot.members")?;
        for source in &self.rebuild.source_denominator {
            bounds::bytes(
                &mut measured_bytes,
                source.target.as_str().len(),
                "snapshot.source.target",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                source.digest.as_str().len(),
                "snapshot.source.digest",
            )?;
            bounds::bytes(&mut measured_bytes, 64, "snapshot.source.structure")?;
            bounds::bytes(
                &mut measured_bytes,
                source.provenance.source_id.as_str().len(),
                "snapshot.source.source_id",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                source.provenance.capture_route.len(),
                "snapshot.source.route",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                source.provenance.scope.len(),
                "snapshot.source.scope",
            )?;
            if let Some(raw_handle) = source.provenance.raw_handle.as_deref() {
                bounds::bytes(
                    &mut measured_bytes,
                    raw_handle.len(),
                    "snapshot.source.raw_handle",
                )?;
            }
            if let Some(revision) = source.provenance.revision.as_deref() {
                bounds::bytes(
                    &mut measured_bytes,
                    revision.len(),
                    "snapshot.source.revision",
                )?;
            }
        }
        for member in &self.members {
            bounds::bytes(
                &mut measured_bytes,
                member.canonical.canonical_cue_id.as_str().len(),
                "snapshot.member.canonical_id",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                member.canonical.canonical_value.len(),
                "snapshot.member.canonical_value",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                member.target.as_str().len(),
                "snapshot.member.target",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                member.canonical.digest.as_str().len(),
                "snapshot.member.canonical_digest",
            )?;
            bounds::bytes(&mut measured_bytes, 64, "snapshot.member.structure")?;
        }
        if let Some(closure) = &self.closure {
            Self::validate_closure_payload_budget(&mut measured_bytes, closure)?;
        }
        Ok(())
    }

    fn validate_closure_payload_budget(
        measured_bytes: &mut usize,
        closure: &CueSnapshotClosure,
    ) -> Result<(), CueContractError> {
        bounds::bytes(measured_bytes, closure.rows.len(), "snapshot.closure.rows")?;
        bounds::bytes(
            measured_bytes,
            closure.relation_edges.len(),
            "snapshot.closure.edges",
        )?;
        bounds::bytes(
            measured_bytes,
            closure.edge_weights.len(),
            "snapshot.closure.weights",
        )?;
        bounds::bytes(measured_bytes, 64, "snapshot.closure.fanout")?;
        for omission in closure
            .denominator
            .row_omissions
            .iter()
            .chain(closure.denominator.edge_omissions.iter())
        {
            bounds::bytes(
                measured_bytes,
                omission.identity.len(),
                "snapshot.closure.omission_identity",
            )?;
            bounds::bytes(measured_bytes, 16, "snapshot.closure.omission_reason")?;
        }
        for row in &closure.rows {
            bounds::bytes(
                measured_bytes,
                row.member.canonical.canonical_value.len(),
                "snapshot.closure.row.value",
            )?;
            bounds::bytes(
                measured_bytes,
                row.key.normalized_value.len(),
                "snapshot.closure.row.key",
            )?;
            bounds::bytes(
                measured_bytes,
                row.source.target.as_str().len(),
                "snapshot.closure.row.source_target",
            )?;
            bounds::bytes(
                measured_bytes,
                row.source.digest.as_str().len(),
                "snapshot.closure.row.source_digest",
            )?;
            bounds::bytes(
                measured_bytes,
                row.source.provenance.source_id.as_str().len()
                    + row.source.provenance.capture_route.len()
                    + row.source.provenance.scope.len(),
                "snapshot.closure.row.source_provenance",
            )?;
            bounds::bytes(
                measured_bytes,
                row.source_member_digest.as_str().len(),
                "snapshot.closure.row.source_member_digest",
            )?;
        }
        for edge in &closure.relation_edges {
            bounds::bytes(
                measured_bytes,
                edge.from.as_str().len() + edge.to.as_str().len(),
                "snapshot.closure.edge.endpoints",
            )?;
        }
        Ok(())
    }
}

fn validate_uniform_scope(
    rows: &[ClosedSnapshotRow],
    sources: &[SourceHandle],
    edges: &[crate::RelationEdge],
) -> Result<(), CueContractError> {
    let mut scopes = BTreeSet::new();
    for row in rows {
        scopes.insert(row.key.scope.as_str());
        scopes.insert(row.source.provenance.scope.as_str());
    }
    for source in sources {
        scopes.insert(source.provenance.scope.as_str());
    }
    for edge in edges {
        scopes.insert(edge.evidence.provenance.scope.as_str());
    }
    if scopes.len() > 1 {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(())
}

fn validate_omission_identities(
    denominator: &CueProjectionDenominator,
    rows: &[ClosedSnapshotRow],
    edges: &[crate::RelationEdge],
) -> Result<(), CueContractError> {
    let retained_rows = rows
        .iter()
        .map(ClosedSnapshotRow::row_id)
        .collect::<Result<BTreeSet<_>, _>>()?;
    let retained_edges = edges
        .iter()
        .map(|edge| edge.relation_edge_id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let mut retained = retained_rows;
    retained.extend(retained_edges);
    if denominator
        .row_omissions
        .iter()
        .chain(denominator.edge_omissions.iter())
        .any(|omission| retained.contains(&omission.identity))
    {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(())
}

fn validate_closed_endpoints(
    members: &[SnapshotMember],
    edges: &[crate::RelationEdge],
) -> Result<(), CueContractError> {
    let endpoints: BTreeSet<_> = members.iter().map(|member| member.target.clone()).collect();
    for edge in edges {
        if !endpoints.contains(&edge.from) || !endpoints.contains(&edge.to) {
            return Err(CueContractError::Foundation {
                field: "snapshot.edge.endpoint",
            });
        }
    }
    Ok(())
}
