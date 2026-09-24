//! Versioned candidate envelope for deterministic cue snapshot builds.

use eliot_receipts::WorkScopeId;
use serde::Serialize;
use std::collections::BTreeSet;

use crate::{
    AdmittedCueBindingProjection, CueContractError, CueSnapshot, CueSnapshotClosure, Digest,
    RelationEdge,
};

/// Independent A-10 envelope revision; the existing cue vocabulary remains 2.0.0.
pub const INDEX_CONTRACT_REVISION: &str = "1.0.0";

#[derive(Serialize)]
struct BuildPreimage {
    schema_revision: String,
    scope_id: WorkScopeId,
    snapshot: CueSnapshot,
    admitted_bindings: Vec<AdmittedCueBindingProjection>,
    relation_edges: Vec<RelationEdge>,
    proof_ceiling: eliot_receipts::ProofCeiling,
}

/// A bounded, deterministic proposal to build an index snapshot.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueSnapshotBuildCandidate {
    pub schema_revision: String,
    pub scope_id: WorkScopeId,
    pub snapshot: CueSnapshot,
    pub admitted_bindings: Vec<AdmittedCueBindingProjection>,
    pub relation_edges: Vec<RelationEdge>,
    pub proof_ceiling: eliot_receipts::ProofCeiling,
    pub build_digest: Digest,
}

impl CueSnapshotBuildCandidate {
    /// Seals a bounded deterministic build candidate under one work scope.
    pub fn seal(
        scope_id: WorkScopeId,
        snapshot: CueSnapshot,
        mut admitted_bindings: Vec<AdmittedCueBindingProjection>,
        mut relation_edges: Vec<RelationEdge>,
    ) -> Result<Self, CueContractError> {
        crate::bounds::text(scope_id.as_str(), "index.scope_id")?;
        let proof_ceiling = eliot_receipts::ProofCeiling::CandidateArtifact;
        crate::index_bounds::build(&snapshot, &admitted_bindings, &relation_edges)?;
        validate_parts(&snapshot, &admitted_bindings, &relation_edges, &scope_id)?;
        admitted_bindings.sort_by(|a, b| {
            a.candidate
                .binding_candidate_id
                .cmp(&b.candidate.binding_candidate_id)
        });
        relation_edges.sort_by(|a, b| a.relation_edge_id.cmp(&b.relation_edge_id));
        let mut value = Self {
            schema_revision: INDEX_CONTRACT_REVISION.to_owned(),
            scope_id,
            snapshot,
            admitted_bindings,
            relation_edges,
            proof_ceiling,
            build_digest: Digest::new("0".repeat(64))?,
        };
        value.build_digest = value.recompute_digest()?;
        Ok(value)
    }

    /// Seals a candidate whose snapshot carries its complete immutable closure.
    ///
    /// The closure is attached before the snapshot digest and the candidate
    /// digest are computed. Consequently `validate`, rebuild, and wire
    /// round-trips cannot silently drop denominator, row, endpoint, weight, or
    /// fanout state.
    pub fn seal_closed(
        scope_id: WorkScopeId,
        mut snapshot: CueSnapshot,
        admitted_bindings: Vec<AdmittedCueBindingProjection>,
        relation_edges: Vec<RelationEdge>,
        closure: CueSnapshotClosure,
    ) -> Result<Self, CueContractError> {
        if !same_edge_set(&closure.relation_edges, &relation_edges) {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        snapshot = snapshot.with_closure(closure);
        snapshot.rebuild.digest = snapshot.canonical_digest()?;
        Self::seal(scope_id, snapshot, admitted_bindings, relation_edges)
    }

    /// Returns whether this candidate carries a self-validating snapshot
    /// closure.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.snapshot.is_closed()
    }

    /// Returns the retained closure, if this candidate is closed.
    #[must_use]
    pub fn retained_closure(&self) -> Option<&CueSnapshotClosure> {
        self.snapshot.retained_closure()
    }

    pub fn validate(&self) -> Result<(), CueContractError> {
        crate::index_bounds::candidate(self)?;
        if self.schema_revision != INDEX_CONTRACT_REVISION
            || self.proof_ceiling != eliot_receipts::ProofCeiling::CandidateArtifact
        {
            return Err(CueContractError::InvalidText {
                field: "index.schema_revision",
            });
        }
        validate_parts(
            &self.snapshot,
            &self.admitted_bindings,
            &self.relation_edges,
            &self.scope_id,
        )?;
        if self.build_digest != self.recompute_digest()? {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }

    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, CueContractError> {
        crate::index_bounds::candidate(self)?;
        if self.schema_revision != INDEX_CONTRACT_REVISION
            || self.proof_ceiling != eliot_receipts::ProofCeiling::CandidateArtifact
        {
            return Err(CueContractError::InvalidText {
                field: "index.schema_revision",
            });
        }
        validate_parts(
            &self.snapshot,
            &self.admitted_bindings,
            &self.relation_edges,
            &self.scope_id,
        )?;
        let mut snapshot = self.snapshot.clone();
        snapshot
            .rebuild
            .source_denominator
            .sort_by(|a, b| a.target.cmp(&b.target).then(a.digest.cmp(&b.digest)));
        snapshot.members.sort_by(|a, b| {
            a.canonical
                .canonical_cue_id
                .cmp(&b.canonical.canonical_cue_id)
                .then(a.target.cmp(&b.target))
        });
        if let Some(closure) = &mut snapshot.closure {
            closure.rows.sort_by(|left, right| {
                left.member
                    .canonical
                    .canonical_cue_id
                    .cmp(&right.member.canonical.canonical_cue_id)
                    .then(left.member.target.cmp(&right.member.target))
            });
            closure
                .relation_edges
                .sort_by(|left, right| left.relation_edge_id.cmp(&right.relation_edge_id));
            closure
                .edge_weights
                .sort_by(|left, right| left.edge.cmp(&right.edge));
        }
        let mut projections = self.admitted_bindings.clone();
        for projection in &mut projections {
            projection
                .normalized
                .comparison_keys
                .sort_by(|a, b| a.comparison_key_id.cmp(&b.comparison_key_id));
        }
        let mut edges = self.relation_edges.clone();
        projections.sort_by(|a, b| {
            a.candidate
                .binding_candidate_id
                .cmp(&b.candidate.binding_candidate_id)
        });
        edges.sort_by(|a, b| a.relation_edge_id.cmp(&b.relation_edge_id));
        let payload = BuildPreimage {
            schema_revision: self.schema_revision.clone(),
            scope_id: self.scope_id.clone(),
            snapshot,
            admitted_bindings: projections,
            relation_edges: edges,
            proof_ceiling: self.proof_ceiling,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&payload).map_err(|_| {
            CueContractError::Foundation {
                field: "index.payload",
            }
        })?;
        if bytes.len() > crate::bounds::MAX_OUTPUT_BYTES - 256 {
            return Err(CueContractError::BoundExceeded {
                field: "index.payload",
                limit: crate::bounds::MAX_OUTPUT_BYTES - 256,
            });
        }
        Ok(bytes)
    }

    fn recompute_digest(&self) -> Result<Digest, CueContractError> {
        Digest::new(eliot_contracts::sha256_hex(
            &self.canonical_payload_bytes()?,
        ))
    }
}

fn validate_parts(
    snapshot: &CueSnapshot,
    projections: &[AdmittedCueBindingProjection],
    edges: &[RelationEdge],
    scope_id: &WorkScopeId,
) -> Result<(), CueContractError> {
    snapshot.validate()?;
    let members = validate_members(snapshot, scope_id)?;
    validate_projections(snapshot, projections, scope_id, &members)?;
    validate_edges(snapshot, edges, scope_id)?;
    if let Some(closure) = snapshot.retained_closure()
        && !same_edge_set(&closure.relation_edges, edges)
    {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(())
}

fn validate_members(
    snapshot: &CueSnapshot,
    scope_id: &WorkScopeId,
) -> Result<
    std::collections::BTreeMap<
        (crate::CanonicalCueId, crate::TargetHandle),
        crate::CanonicalCueIdentity,
    >,
    CueContractError,
> {
    let mut members = std::collections::BTreeMap::new();
    let mut canonical_by_id = std::collections::BTreeMap::new();
    for member in &snapshot.members {
        if members
            .insert(
                (
                    member.canonical.canonical_cue_id.clone(),
                    member.target.clone(),
                ),
                member.canonical.clone(),
            )
            .is_some()
        {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.members",
            });
        }
        if let Some(existing) = canonical_by_id.insert(
            member.canonical.canonical_cue_id.clone(),
            member.canonical.clone(),
        ) && existing != member.canonical
        {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.member_canonical",
            });
        }
    }
    for source in &snapshot.rebuild.source_denominator {
        if source.provenance.scope != scope_id.as_str() {
            return Err(CueContractError::Foundation {
                field: "index.source.scope",
            });
        }
        if snapshot.is_closed()
            && !crate::version::source_revision_matches(source, snapshot.source_revision)
        {
            return Err(CueContractError::Foundation {
                field: "index.source.revision",
            });
        }
    }
    Ok(members)
}

fn validate_projections(
    snapshot: &CueSnapshot,
    projections: &[AdmittedCueBindingProjection],
    scope_id: &WorkScopeId,
    members: &std::collections::BTreeMap<
        (crate::CanonicalCueId, crate::TargetHandle),
        crate::CanonicalCueIdentity,
    >,
) -> Result<(), CueContractError> {
    let mut candidates = BTreeSet::new();
    let mut matched = BTreeSet::new();
    let mut matched_sources = BTreeSet::new();
    let mut comparison_keys = std::collections::BTreeMap::new();
    let mut sources = std::collections::BTreeMap::new();
    for source in &snapshot.rebuild.source_denominator {
        sources.insert((source.target.clone(), source.digest.clone()), source);
    }
    for projection in projections {
        projection.validate()?;
        if !candidates.insert(projection.candidate.binding_candidate_id.clone()) {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.candidates",
            });
        }
        let key = (
            projection.candidate.canonical.canonical_cue_id.clone(),
            projection.candidate.target.clone(),
        );
        if !members.contains_key(&key) || !matched.insert(key.clone()) {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        if members.get(&key) != Some(&projection.candidate.canonical) {
            return Err(CueContractError::Foundation {
                field: "index.member_canonical",
            });
        }
        for comparison_key in &projection.normalized.comparison_keys {
            if let Some(existing) = comparison_keys.insert(
                comparison_key.comparison_key_id.clone(),
                comparison_key.clone(),
            ) && existing != *comparison_key
            {
                return Err(CueContractError::DuplicateIdentity {
                    field: "index.comparison_key",
                });
            }
        }
        if projection.normalized.profile != snapshot.rebuild.normalization_profile
            || projection.normalized.observed.context.state_fence != snapshot.state_fence
            || &projection.normalized.observed.context.scope_id != scope_id
        {
            return Err(CueContractError::Foundation {
                field: "index.profile_fence",
            });
        }
        let source = &projection.normalized.observed.source;
        if source.provenance.scope != scope_id.as_str()
            || projection
                .normalized
                .observed
                .context
                .evidence
                .provenance
                .scope
                != scope_id.as_str()
        {
            return Err(CueContractError::Foundation {
                field: "index.scope",
            });
        }
        let source_key = (source.target.clone(), source.digest.clone());
        if sources.get(&source_key) != Some(&source) {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        if let Some(closure) = snapshot.retained_closure() {
            validate_retained_projection_row(closure, projection, scope_id)?;
        }
        matched_sources.insert(source_key);
    }
    if matched.len() != members.len()
        || projections.len() != members.len()
        || matched_sources.len() != sources.len()
    {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(())
}

fn validate_retained_projection_row(
    closure: &CueSnapshotClosure,
    projection: &AdmittedCueBindingProjection,
    scope_id: &WorkScopeId,
) -> Result<(), CueContractError> {
    let source = &projection.normalized.observed.source;
    if !crate::version::source_revision_matches(source, closure.denominator.source_revision) {
        return Err(CueContractError::Foundation {
            field: "index.source.revision",
        });
    }
    let row = closure
        .rows
        .iter()
        .find(|row| {
            row.member.canonical.canonical_cue_id == projection.candidate.canonical.canonical_cue_id
                && row.member.target == projection.candidate.target
        })
        .ok_or(CueContractError::SnapshotNotRebuildable)?;
    let primary = projection
        .normalized
        .comparison_keys
        .first()
        .ok_or(CueContractError::SnapshotNotRebuildable)?;
    let expected_member = crate::SnapshotMember::new(
        projection.candidate.canonical.clone(),
        projection.candidate.target.clone(),
    );
    if row.member != expected_member
        || &row.source != source
        || row.key.scope != scope_id.as_str()
        || row.key.kind != projection.candidate.canonical.kind
        || row.key.mode != primary.match_mode
        || row.key.normalized_value != primary.key_value
        || row.source_revision != closure.denominator.source_revision
    {
        return Err(CueContractError::Foundation {
            field: "index.row.source",
        });
    }
    Ok(())
}

fn validate_edges(
    snapshot: &CueSnapshot,
    edges: &[RelationEdge],
    scope_id: &WorkScopeId,
) -> Result<(), CueContractError> {
    let endpoints: BTreeSet<_> = snapshot
        .members
        .iter()
        .map(|member| member.target.clone())
        .collect();
    let mut edge_ids = BTreeSet::new();
    for edge in edges {
        edge.validate()?;
        if !edge_ids.insert(edge.relation_edge_id.clone()) {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.edges",
            });
        }
        if !endpoints.contains(&edge.from) || !endpoints.contains(&edge.to) {
            return Err(CueContractError::Foundation {
                field: "index.edge.endpoint",
            });
        }
        if edge.evidence.state_fence != snapshot.state_fence {
            return Err(CueContractError::Foundation {
                field: "index.edge.fence",
            });
        }
        if edge.evidence.provenance.scope != scope_id.as_str() {
            return Err(CueContractError::Foundation {
                field: "index.edge.scope",
            });
        }
        if snapshot.is_closed()
            && !crate::version::revision_marker_matches(
                edge.evidence.provenance.revision.as_deref(),
                snapshot.source_revision,
            )
        {
            return Err(CueContractError::Foundation {
                field: "index.edge.revision",
            });
        }
    }
    Ok(())
}

fn same_edge_set(left: &[RelationEdge], right: &[RelationEdge]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_by(|a, b| a.relation_edge_id.cmp(&b.relation_edge_id));
    right.sort_by(|a, b| a.relation_edge_id.cmp(&b.relation_edge_id));
    left == right
}
