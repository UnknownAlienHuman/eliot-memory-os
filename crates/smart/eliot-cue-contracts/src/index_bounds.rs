//! Bounded preflight for the additive snapshot-build envelope.

use crate::{
    AdmittedCueBindingProjection, CueContractError, CueSnapshot, CueSnapshotBuildCandidate,
    RelationEdge,
};

pub(crate) const MAX_INDEX_ITEMS: usize = 4_096;
pub(crate) const MAX_INDEX_EDGES: usize = crate::MAX_RELATION_EDGES;
pub(crate) const MAX_INDEX_INPUT_BYTES: usize = crate::bounds::MAX_OUTPUT_BYTES;

fn add(total: &mut usize, amount: usize, field: &'static str) -> Result<(), CueContractError> {
    *total = total
        .checked_add(amount)
        .ok_or(CueContractError::BoundExceeded {
            field,
            limit: MAX_INDEX_INPUT_BYTES,
        })?;
    if *total > MAX_INDEX_INPUT_BYTES {
        return Err(CueContractError::BoundExceeded {
            field,
            limit: MAX_INDEX_INPUT_BYTES,
        });
    }
    Ok(())
}

fn text(total: &mut usize, value: &str, field: &'static str) -> Result<(), CueContractError> {
    crate::bounds::text(value, field)?;
    let encoded_upper = value
        .len()
        .checked_mul(6)
        .ok_or(CueContractError::BoundExceeded {
            field,
            limit: MAX_INDEX_INPUT_BYTES,
        })?;
    add(total, encoded_upper, field)
}

fn digest(
    total: &mut usize,
    value: &crate::Digest,
    field: &'static str,
) -> Result<(), CueContractError> {
    let encoded_upper =
        value
            .as_str()
            .len()
            .checked_mul(6)
            .ok_or(CueContractError::BoundExceeded {
                field,
                limit: MAX_INDEX_INPUT_BYTES,
            })?;
    add(total, encoded_upper, field)
}

fn provenance(
    total: &mut usize,
    value: &eliot_evidence::Provenance,
    field: &'static str,
) -> Result<(), CueContractError> {
    text(total, value.source_id.as_str(), field)?;
    text(total, &value.capture_route, field)?;
    text(total, &value.scope, field)?;
    if let Some(value) = value.raw_handle.as_deref() {
        text(total, value, field)?;
    }
    if let Some(value) = value.revision.as_deref() {
        text(total, value, field)?;
    }
    Ok(())
}

fn context(total: &mut usize, value: &crate::CueContext) -> Result<(), CueContractError> {
    text(total, value.task_id.as_str(), "index.context.task_id")?;
    text(total, value.scope_id.as_str(), "index.context.scope_id")?;
    provenance(
        total,
        &value.evidence.provenance,
        "index.context.provenance",
    )?;
    if let Some(v) = value.evidence.verification.as_ref() {
        text(total, v.contract_id.as_str(), "index.context.verification")?;
        text(total, v.run_id.as_str(), "index.context.verification")?;
        text(total, &v.revision, "index.context.verification")?;
    }
    Ok(())
}

fn observed(total: &mut usize, value: &crate::ObservedCue) -> Result<(), CueContractError> {
    text(
        total,
        &value.schema_revision,
        "index.observed.schema_revision",
    )?;
    text(total, value.observed_cue_id.as_str(), "index.observed.id")?;
    text(total, &value.original_value, "index.observed.value")?;
    text(total, value.source.target.as_str(), "index.source.target")?;
    digest(total, &value.source.digest, "index.source.digest")?;
    provenance(total, &value.source.provenance, "index.source.provenance")?;
    context(total, &value.context)
}

fn normalized(total: &mut usize, value: &crate::NormalizedCue) -> Result<(), CueContractError> {
    text(
        total,
        &value.schema_revision,
        "index.normalized.schema_revision",
    )?;
    observed(total, &value.observed)?;
    text(total, &value.profile.profile_id, "index.profile.id")?;
    digest(total, &value.profile.digest, "index.profile.digest")?;
    if let Some(c) = value.canonical.as_ref() {
        text(total, c.canonical_cue_id.as_str(), "index.canonical.id")?;
        text(total, &c.canonical_value, "index.canonical.value")?;
        digest(total, &c.digest, "index.canonical.digest")?;
    }
    if value.comparison_keys.len() > crate::MAX_COMPARISON_KEYS {
        return Err(CueContractError::BoundExceeded {
            field: "index.comparison_keys",
            limit: crate::MAX_COMPARISON_KEYS,
        });
    }
    add(total, value.comparison_keys.len(), "index.comparison_keys")?;
    for key in &value.comparison_keys {
        text(total, key.comparison_key_id.as_str(), "index.key.id")?;
        text(total, &key.profile.profile_id, "index.key.profile")?;
        digest(total, &key.profile.digest, "index.key.digest")?;
        text(total, &key.key_value, "index.key.value")?;
    }
    if value.transformation_evidence.len() > crate::MAX_TRANSFORMATION_STEPS {
        return Err(CueContractError::BoundExceeded {
            field: "index.transformations",
            limit: crate::MAX_TRANSFORMATION_STEPS,
        });
    }
    add(
        total,
        value.transformation_evidence.len(),
        "index.transformations",
    )?;
    for step in &value.transformation_evidence {
        text(total, &step.step, "index.transformation.step")?;
        text(total, &step.result, "index.transformation.result")?;
    }
    match &value.outcome {
        crate::NormalizationOutcome::AuthorizedLoss { policy_ref } => {
            text(total, policy_ref, "index.outcome.policy")?;
        }
        crate::NormalizationOutcome::Ambiguous { rivals } => {
            if rivals.len() > crate::MAX_COMPARISON_KEYS {
                return Err(CueContractError::BoundExceeded {
                    field: "index.outcome.rivals",
                    limit: crate::MAX_COMPARISON_KEYS,
                });
            }
            add(total, rivals.len(), "index.outcome.rivals")?;
            for rival in rivals {
                text(total, rival.canonical_cue_id.as_str(), "index.rival.id")?;
                text(total, &rival.canonical_value, "index.rival.value")?;
                digest(total, &rival.digest, "index.rival.digest")?;
            }
        }
        crate::NormalizationOutcome::Unsupported { reason } => {
            text(total, reason, "index.outcome.reason")?;
        }
        crate::NormalizationOutcome::Lossless => {}
    }
    Ok(())
}

pub(crate) fn projection(
    total: &mut usize,
    value: &AdmittedCueBindingProjection,
) -> Result<(), CueContractError> {
    candidate_and_normalized(total, &value.candidate, &value.normalized)?;
    // Covers bounded nested containers, fixed field names, enums and fences.
    add(total, 32_768, "index.projection.structure")?;
    text(
        total,
        value.admission.receipt.receipt_id.as_str(),
        "index.admission.receipt",
    )?;
    text(
        total,
        &value.admission.receipt.canonical_sha256,
        "index.admission.receipt_digest",
    )?;
    text(
        total,
        value.admission.candidate_id.as_str(),
        "index.admission.candidate_id",
    )?;
    digest(
        total,
        &value.admission.candidate_digest,
        "index.admission.candidate_digest",
    )?;
    text(
        total,
        value.admission.task_id.as_str(),
        "index.admission.task_id",
    )?;
    text(
        total,
        value.admission.scope_id.as_str(),
        "index.admission.scope_id",
    )
}

pub(crate) fn candidate_and_normalized(
    total: &mut usize,
    candidate: &crate::CueBindingCandidate,
    normalized_value: &crate::NormalizedCue,
) -> Result<(), CueContractError> {
    text(
        total,
        candidate.binding_candidate_id.as_str(),
        "index.candidate.id",
    )?;
    text(total, candidate.target.as_str(), "index.candidate.target")?;
    text(
        total,
        candidate.canonical.canonical_cue_id.as_str(),
        "index.candidate.canonical.id",
    )?;
    text(
        total,
        &candidate.canonical.canonical_value,
        "index.candidate.canonical.value",
    )?;
    digest(
        total,
        &candidate.canonical.digest,
        "index.candidate.canonical.digest",
    )?;
    digest(total, &candidate.digest, "index.candidate.digest")?;
    normalized(total, normalized_value)
}

pub(crate) fn edge(total: &mut usize, value: &RelationEdge) -> Result<(), CueContractError> {
    text(total, value.relation_edge_id.as_str(), "index.edge.id")?;
    text(total, value.from.as_str(), "index.edge.from")?;
    text(total, value.to.as_str(), "index.edge.to")?;
    text(total, &value.registry_revision, "index.edge.registry")?;
    digest(total, &value.edge_digest, "index.edge.digest")?;
    provenance(total, &value.evidence.provenance, "index.edge.provenance")?;
    // Covers fixed edge fields, enum/fence encoding and structural JSON bytes.
    add(total, 4_096, "index.edge.structure")?;
    if let Some(v) = value.evidence.verification.as_ref() {
        text(total, v.contract_id.as_str(), "index.edge.verification")?;
        text(total, v.run_id.as_str(), "index.edge.verification")?;
        text(total, &v.revision, "index.edge.verification")?;
    }
    Ok(())
}

pub(crate) fn build(
    value: &CueSnapshot,
    projections: &[AdmittedCueBindingProjection],
    edges: &[RelationEdge],
) -> Result<(), CueContractError> {
    let mut total = 0;
    build_with_total(&mut total, value, projections, edges)
}

fn build_with_total(
    total: &mut usize,
    value: &CueSnapshot,
    projections: &[AdmittedCueBindingProjection],
    edges: &[RelationEdge],
) -> Result<(), CueContractError> {
    if projections.len() > MAX_INDEX_ITEMS {
        return Err(CueContractError::BoundExceeded {
            field: "index.projections",
            limit: MAX_INDEX_ITEMS,
        });
    }
    if edges.len() > MAX_INDEX_EDGES {
        return Err(CueContractError::BoundExceeded {
            field: "index.edges",
            limit: MAX_INDEX_EDGES,
        });
    }
    let records = projections
        .len()
        .checked_add(edges.len())
        .and_then(|count| count.checked_add(value.members.len()))
        .and_then(|count| count.checked_add(value.rebuild.source_denominator.len()))
        .ok_or(CueContractError::BoundExceeded {
            field: "index.records",
            limit: MAX_INDEX_INPUT_BYTES,
        })?;
    let structural_overhead = records
        .checked_mul(256)
        .ok_or(CueContractError::BoundExceeded {
            field: "index.records",
            limit: MAX_INDEX_INPUT_BYTES,
        })?;
    add(total, structural_overhead, "index.records")?;
    text(total, &value.schema_revision, "index.snapshot.schema")?;
    text(total, value.snapshot_id.as_str(), "index.snapshot.id")?;
    text(
        total,
        &value.rebuild.normalization_profile.profile_id,
        "index.snapshot.profile",
    )?;
    digest(
        total,
        &value.rebuild.normalization_profile.digest,
        "index.snapshot.profile_digest",
    )?;
    digest(total, &value.rebuild.digest, "index.snapshot.digest")?;
    if value.members.len() > MAX_INDEX_ITEMS
        || value.rebuild.source_denominator.len() > MAX_INDEX_ITEMS
    {
        return Err(CueContractError::BoundExceeded {
            field: "index.snapshot.members",
            limit: MAX_INDEX_ITEMS,
        });
    }
    for source in &value.rebuild.source_denominator {
        text(total, source.target.as_str(), "index.snapshot.source")?;
        digest(total, &source.digest, "index.snapshot.source_digest")?;
        provenance(
            total,
            &source.provenance,
            "index.snapshot.source_provenance",
        )?;
    }
    for member in &value.members {
        text(total, member.target.as_str(), "index.snapshot.member")?;
        text(
            total,
            member.canonical.canonical_cue_id.as_str(),
            "index.snapshot.member_id",
        )?;
        text(
            total,
            &member.canonical.canonical_value,
            "index.snapshot.member_value",
        )?;
        digest(
            total,
            &member.canonical.digest,
            "index.snapshot.member_digest",
        )?;
    }
    for projection_value in projections {
        projection(total, projection_value)?;
    }
    for edge_value in edges {
        edge(total, edge_value)?;
    }
    Ok(())
}

pub(crate) fn candidate(value: &CueSnapshotBuildCandidate) -> Result<(), CueContractError> {
    let mut total = 0;
    text(&mut total, &value.schema_revision, "index.schema_revision")?;
    text(&mut total, value.scope_id.as_str(), "index.scope_id")?;
    build_with_total(
        &mut total,
        &value.snapshot,
        &value.admitted_bindings,
        &value.relation_edges,
    )
}
