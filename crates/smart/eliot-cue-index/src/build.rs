//! Pure construction and rebuild of one A-10 snapshot-build candidate.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::StateFence;
use eliot_cue_contracts::{
    AdmittedCueBindingProjection, CONTRACT_REVISION, ClosedSnapshotRow, CueComparisonKey,
    CueContractError, CueProjectionDenominator, CueSnapshot, CueSnapshotBuildCandidate,
    CueSnapshotClosure, CueSnapshotFanout, Digest, NormalizationProfile, RebuildIdentity,
    RelationEdge, SnapshotEdgeWeight, SnapshotId, SnapshotMember, WorkScopeId,
};
use eliot_evidence::{EpistemicStatus, EvidenceFreshness};

use crate::bounds;

/// Builds an immutable candidate from exact A-10 projections and typed edges.
///
/// The registry revision is compared with every supplied edge. The operation
/// only validates and composes caller-supplied records; `None` is valid for an
/// empty edge set and a non-empty set requires an explicit revision. This
/// strict all-or-error prototype accepts only active records with one of the
/// exact freshness labels and observed, supported, or verified evidence status.
/// Its bounded input cap is 512 KiB. It does not authenticate admission,
/// publish a snapshot, or provide a complete rejection report.
pub fn build_cue_snapshot(
    scope_id: &WorkScopeId,
    snapshot_id: SnapshotId,
    profile: NormalizationProfile,
    state_fence: StateFence,
    projections: &[AdmittedCueBindingProjection],
    relation_edges: &[RelationEdge],
    registry_revision: Option<&str>,
) -> Result<CueSnapshotBuildCandidate, CueContractError> {
    let total = preflight_input(
        scope_id,
        &snapshot_id,
        &profile,
        projections,
        relation_edges,
        registry_revision,
    )?;
    bounds::measure_records(total, projections, relation_edges)?;
    validate_inputs(
        scope_id,
        &profile,
        &state_fence,
        projections,
        relation_edges,
        registry_revision,
    )?;
    let (members, sources) = derive_members_and_sources(projections)?;
    let mut snapshot = CueSnapshot::new(
        CONTRACT_REVISION.to_owned(),
        snapshot_id,
        members,
        RebuildIdentity::new(profile, sources, Digest::new("0".repeat(64))?),
        state_fence,
    );
    snapshot.rebuild.digest = snapshot.canonical_digest()?;
    CueSnapshotBuildCandidate::seal(
        scope_id.clone(),
        snapshot,
        projections.to_vec(),
        relation_edges.to_vec(),
    )
}

/// Rebuilds the candidate using only its retained canonical inputs and the
/// caller's expected edge-registry revision. Both canonical bytes and the
/// sealed digest must match the retained candidate.
pub fn rebuild_cue_snapshot(
    candidate: &CueSnapshotBuildCandidate,
    registry_revision: Option<&str>,
) -> Result<CueSnapshotBuildCandidate, CueContractError> {
    candidate.validate()?;
    if let Some(closure) = candidate.snapshot.retained_closure() {
        return rebuild_cue_snapshot_with_closure(candidate, registry_revision, closure);
    }
    let rebuilt = build_cue_snapshot(
        &candidate.scope_id,
        candidate.snapshot.snapshot_id.clone(),
        candidate.snapshot.rebuild.normalization_profile.clone(),
        candidate.snapshot.state_fence.clone(),
        &candidate.admitted_bindings,
        &candidate.relation_edges,
        registry_revision,
    )?;
    if rebuilt.build_digest != candidate.build_digest
        || rebuilt.canonical_payload_bytes()? != candidate.canonical_payload_bytes()?
    {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(rebuilt)
}

/// Builds a closed candidate: exact build plus frozen denominator, row
/// identity, endpoint, and weight closure.
///
/// Each member is joined to the primary (first) comparison key of the exact
/// admitted projection it was built from; scope comes from the build scope.
/// Keyless projections carry no comparison material and fail closed rather
/// than defaulting to source spelling. `weights` supplies exactly one
/// policy-owned milli weight per edge. An explicitly partial denominator
/// (nonzero omissions that reconcile) is accepted; use
/// [`CueProjectionDenominator::is_empty_complete`] to classify the result.
#[allow(
    clippy::too_many_arguments,
    reason = "the closed build threads the exact open-build inputs plus the frozen denominator and weights; splitting the signature would hide the closure"
)]
pub fn build_cue_snapshot_closed(
    scope_id: &WorkScopeId,
    snapshot_id: SnapshotId,
    profile: NormalizationProfile,
    state_fence: StateFence,
    projections: &[AdmittedCueBindingProjection],
    relation_edges: &[RelationEdge],
    registry_revision: Option<&str>,
    denominator: &CueProjectionDenominator,
    weights: &[SnapshotEdgeWeight],
) -> Result<CueSnapshotBuildCandidate, CueContractError> {
    denominator.validate()?;
    let candidate = build_cue_snapshot(
        scope_id,
        snapshot_id,
        profile,
        state_fence,
        projections,
        relation_edges,
        registry_revision,
    )?;
    let rows = join_closed_rows(
        scope_id,
        &candidate.snapshot.members,
        projections,
        denominator.source_revision,
    )?;
    let closed_weights = bind_weights_at_revision(weights, denominator.source_revision)?;
    let closure = CueSnapshotClosure::new(
        *denominator,
        rows,
        relation_edges.to_vec(),
        closed_weights,
        fanout_for(relation_edges.len()),
    );
    let mut snapshot = candidate.snapshot.with_closure(closure.clone());
    snapshot.rebuild.digest = snapshot.canonical_digest()?;
    snapshot.validate_self_closed()?;
    let closed = CueSnapshotBuildCandidate::seal_closed(
        scope_id.clone(),
        snapshot,
        candidate.admitted_bindings,
        candidate.relation_edges,
        closure,
    )?;
    Ok(closed)
}

/// Rebuilds a closed candidate and re-proves its retained closure.
///
/// When the candidate is already closed, the supplied denominator and weights
/// are checked against the retained values and are not allowed to replace
/// them. Older open candidates are upgraded only through the explicit closed
/// seam below.
pub fn rebuild_cue_snapshot_closed(
    candidate: &CueSnapshotBuildCandidate,
    registry_revision: Option<&str>,
    denominator: &CueProjectionDenominator,
    weights: &[SnapshotEdgeWeight],
) -> Result<CueSnapshotBuildCandidate, CueContractError> {
    if let Some(retained) = candidate.snapshot.retained_closure() {
        if *denominator != retained.denominator || weights != retained.edge_weights.as_slice() {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        return rebuild_cue_snapshot_with_closure(candidate, registry_revision, retained);
    }
    let rebuilt = rebuild_cue_snapshot(candidate, registry_revision)?;
    let rows = join_closed_rows(
        &rebuilt.scope_id,
        &rebuilt.snapshot.members,
        &rebuilt.admitted_bindings,
        denominator.source_revision,
    )?;
    let closed_weights = bind_weights_at_revision(weights, denominator.source_revision)?;
    let closure = CueSnapshotClosure::new(
        *denominator,
        rows,
        rebuilt.relation_edges.clone(),
        closed_weights,
        fanout_for(rebuilt.relation_edges.len()),
    );
    let mut snapshot = rebuilt.snapshot.with_closure(closure.clone());
    snapshot.rebuild.digest = snapshot.canonical_digest()?;
    snapshot.validate_self_closed()?;
    CueSnapshotBuildCandidate::seal_closed(
        rebuilt.scope_id.clone(),
        snapshot,
        rebuilt.admitted_bindings,
        rebuilt.relation_edges,
        closure,
    )
}

fn rebuild_cue_snapshot_with_closure(
    candidate: &CueSnapshotBuildCandidate,
    registry_revision: Option<&str>,
    closure: &CueSnapshotClosure,
) -> Result<CueSnapshotBuildCandidate, CueContractError> {
    let rebuilt = build_cue_snapshot(
        &candidate.scope_id,
        candidate.snapshot.snapshot_id.clone(),
        candidate.snapshot.rebuild.normalization_profile.clone(),
        candidate.snapshot.state_fence.clone(),
        &candidate.admitted_bindings,
        &candidate.relation_edges,
        registry_revision,
    )?;
    let mut snapshot = rebuilt.snapshot.with_closure(closure.clone());
    snapshot.rebuild.digest = snapshot.canonical_digest()?;
    let result = CueSnapshotBuildCandidate::seal_closed(
        rebuilt.scope_id,
        snapshot,
        rebuilt.admitted_bindings,
        rebuilt.relation_edges,
        closure.clone(),
    )?;
    if result.build_digest != candidate.build_digest
        || result.canonical_payload_bytes()? != candidate.canonical_payload_bytes()?
    {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    Ok(result)
}

fn bind_weights_at_revision(
    weights: &[SnapshotEdgeWeight],
    source_revision: u64,
) -> Result<Vec<SnapshotEdgeWeight>, CueContractError> {
    if source_revision == 0
        || weights
            .iter()
            .any(|weight| weight.source_revision != source_revision)
    {
        return Err(CueContractError::Foundation {
            field: "index.edge_weight.source_revision",
        });
    }
    // Preserve the supplied records byte-for-byte. A missing, stale, or
    // mismatched revision is a refusal, never an opportunity for the builder
    // to rewrite policy input into the denominator revision.
    Ok(weights.to_vec())
}

fn fanout_for(edge_count: usize) -> CueSnapshotFanout {
    if edge_count == 0 {
        CueSnapshotFanout::direct_only()
    } else {
        CueSnapshotFanout::bounded(
            u8::try_from(eliot_cue_contracts::MAX_PATH_LEN).unwrap_or(u8::MAX),
            u16::try_from(eliot_cue_contracts::MAX_RELATION_EDGES).unwrap_or(u16::MAX),
            u32::try_from(eliot_cue_contracts::MAX_RELATION_EDGES).unwrap_or(u32::MAX),
            u16::try_from(eliot_cue_contracts::MAX_PATH_LEN).unwrap_or(u16::MAX),
        )
    }
}

fn join_closed_rows(
    scope_id: &WorkScopeId,
    members: &[SnapshotMember],
    projections: &[AdmittedCueBindingProjection],
    source_revision: u64,
) -> Result<Vec<ClosedSnapshotRow>, CueContractError> {
    let mut by_member = BTreeMap::new();
    for projection in projections {
        let key = (
            projection.candidate.canonical.canonical_cue_id.clone(),
            projection.candidate.target.clone(),
        );
        if by_member.insert(key, projection).is_some() {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.closed_rows.projections",
            });
        }
    }
    if by_member.len() != members.len() {
        return Err(CueContractError::SnapshotNotRebuildable);
    }
    let mut rows = Vec::with_capacity(members.len());
    for member in members {
        let key = (
            member.canonical.canonical_cue_id.clone(),
            member.target.clone(),
        );
        let Some(projection) = by_member.get(&key) else {
            return Err(CueContractError::SnapshotNotRebuildable);
        };
        let Some(primary) = projection.normalized.comparison_keys.first() else {
            return Err(CueContractError::SnapshotNotRebuildable);
        };
        let comparison = CueComparisonKey::new(
            scope_id.as_str().to_owned(),
            projection.candidate.canonical.kind,
            primary.match_mode,
            primary.key_value.clone(),
        );
        let row = ClosedSnapshotRow::new_at_revision(
            member.clone(),
            comparison,
            projection.normalized.observed.source.clone(),
            source_revision,
        );
        row.validate()?;
        rows.push(row);
    }
    Ok(rows)
}

fn preflight_input(
    scope_id: &WorkScopeId,
    snapshot_id: &SnapshotId,
    profile: &NormalizationProfile,
    projections: &[AdmittedCueBindingProjection],
    relation_edges: &[RelationEdge],
    registry_revision: Option<&str>,
) -> Result<usize, CueContractError> {
    bounds::preflight(
        scope_id,
        snapshot_id,
        profile,
        projections,
        relation_edges,
        registry_revision,
    )
}

fn validate_inputs(
    scope_id: &WorkScopeId,
    profile: &NormalizationProfile,
    state_fence: &StateFence,
    projections: &[AdmittedCueBindingProjection],
    relation_edges: &[RelationEdge],
    registry_revision: Option<&str>,
) -> Result<(), CueContractError> {
    profile.validate()?;
    state_fence
        .validate()
        .map_err(|_| CueContractError::Foundation {
            field: "index.state_fence",
        })?;
    let mut candidate_ids = BTreeSet::new();
    for projection in projections {
        if !supported_freshness(projection.candidate.freshness)
            || !supported_freshness(projection.normalized.observed.context.evidence.freshness)
            || !supported_status(projection.normalized.observed.context.evidence.status)
            || !projection.normalized.observed.context.lifecycle.is_active()
        {
            return Err(CueContractError::Foundation {
                field: "index.currentness",
            });
        }
        if &projection.normalized.profile != profile
            || &projection.normalized.observed.context.scope_id != scope_id
            || &projection.normalized.observed.context.state_fence != state_fence
            || &projection.admission.state_fence != state_fence
        {
            return Err(CueContractError::Foundation {
                field: "index.binding",
            });
        }
        if !candidate_ids.insert(projection.candidate.binding_candidate_id.clone()) {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.candidate_ids",
            });
        }
    }
    validate_edges(state_fence, scope_id, relation_edges, registry_revision)
}

fn validate_edges(
    state_fence: &StateFence,
    scope_id: &WorkScopeId,
    relation_edges: &[RelationEdge],
    registry_revision: Option<&str>,
) -> Result<(), CueContractError> {
    let mut edge_ids = BTreeSet::new();
    for edge in relation_edges {
        if !edge_ids.insert(edge.relation_edge_id.clone()) {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.edge_ids",
            });
        }
        let Some(expected_registry_revision) = registry_revision else {
            return Err(CueContractError::Foundation {
                field: "index.registry_revision",
            });
        };
        if edge.registry_revision != expected_registry_revision
            || &edge.evidence.state_fence != state_fence
            || !supported_freshness(edge.evidence.freshness)
            || !supported_status(edge.evidence.status)
            || edge.evidence.provenance.scope != scope_id.as_str()
        {
            return Err(CueContractError::Foundation {
                field: "index.edge_binding",
            });
        }
    }
    Ok(())
}

const fn supported_status(value: EpistemicStatus) -> bool {
    matches!(
        value,
        EpistemicStatus::Observed | EpistemicStatus::Supported | EpistemicStatus::Verified
    )
}

const fn supported_freshness(value: EvidenceFreshness) -> bool {
    matches!(
        value,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    )
}

fn derive_members_and_sources(
    projections: &[AdmittedCueBindingProjection],
) -> Result<(Vec<SnapshotMember>, Vec<eliot_cue_contracts::SourceHandle>), CueContractError> {
    let mut members = Vec::with_capacity(projections.len());
    let mut member_keys = BTreeSet::new();
    let mut canonical_by_id = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for projection in projections {
        let canonical = projection.candidate.canonical.clone();
        let member_key = (
            canonical.canonical_cue_id.clone(),
            projection.candidate.target.clone(),
        );
        if !member_keys.insert(member_key) {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.members",
            });
        }
        if let Some(existing) =
            canonical_by_id.insert(canonical.canonical_cue_id.clone(), canonical.clone())
            && existing != canonical
        {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.canonical_ids",
            });
        }
        members.push(SnapshotMember::new(
            canonical,
            projection.candidate.target.clone(),
        ));
        let source = projection.normalized.observed.source.clone();
        let source_key = (source.target.clone(), source.digest.clone());
        if let Some(existing) = sources.insert(source_key, source.clone())
            && existing != source
        {
            return Err(CueContractError::DuplicateIdentity {
                field: "index.sources",
            });
        }
    }
    members.sort_by(|left, right| {
        left.canonical
            .canonical_cue_id
            .cmp(&right.canonical.canonical_cue_id)
            .then_with(|| left.target.cmp(&right.target))
    });
    Ok((members, sources.into_values().collect()))
}
