//! Pure construction and rebuild of one A-10 snapshot-build candidate.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::StateFence;
use eliot_cue_contracts::{
    AdmittedCueBindingProjection, CONTRACT_REVISION, CueContractError, CueSnapshot,
    CueSnapshotBuildCandidate, Digest, NormalizationProfile, RebuildIdentity, RelationEdge,
    SnapshotId, SnapshotMember, WorkScopeId,
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
