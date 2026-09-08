//! Borrowed input bounds for the snapshot builder.

use eliot_cue_contracts::{AdmittedCueBindingProjection, CueContractError, RelationEdge};

pub(crate) const MAX_BINDINGS: usize = 128;
pub(crate) const MAX_EDGES: usize = 128;
pub(crate) const MAX_INPUT_BYTES: usize = 512 * 1024;
const MAX_TEXT_BYTES: usize = 8 * 1024;

fn add(total: &mut usize, amount: usize, field: &'static str) -> Result<(), CueContractError> {
    *total = total
        .checked_add(amount)
        .ok_or(CueContractError::BoundExceeded {
            field,
            limit: MAX_INPUT_BYTES,
        })?;
    if *total > MAX_INPUT_BYTES {
        return Err(CueContractError::BoundExceeded {
            field,
            limit: MAX_INPUT_BYTES,
        });
    }
    Ok(())
}

fn text(total: &mut usize, value: &str, field: &'static str) -> Result<(), CueContractError> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(CueContractError::BoundExceeded {
            field,
            limit: MAX_TEXT_BYTES,
        });
    }
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CueContractError::InvalidText { field });
    }
    let encoded_upper = value
        .len()
        .checked_mul(6)
        .ok_or(CueContractError::BoundExceeded {
            field,
            limit: MAX_INPUT_BYTES,
        })?;
    add(total, encoded_upper, field)
}

/// Bounds the cheap scalar/header portion before any owner validator or clone.
pub(crate) fn preflight(
    scope: &eliot_cue_contracts::WorkScopeId,
    snapshot_id: &eliot_cue_contracts::SnapshotId,
    profile: &eliot_cue_contracts::NormalizationProfile,
    projections: &[AdmittedCueBindingProjection],
    edges: &[RelationEdge],
    registry_revision: Option<&str>,
) -> Result<usize, CueContractError> {
    if projections.len() > MAX_BINDINGS {
        return Err(CueContractError::BoundExceeded {
            field: "index.bindings",
            limit: MAX_BINDINGS,
        });
    }
    if edges.len() > MAX_EDGES {
        return Err(CueContractError::BoundExceeded {
            field: "index.edges",
            limit: MAX_EDGES,
        });
    }
    let mut total = 0;
    // Reserve framing, fixed field names, numeric fences and enum tags before
    // any owner validation or per-record canonical encoding.
    add(&mut total, 4_096, "index.input")?;
    text(&mut total, scope.as_str(), "index.scope")?;
    text(&mut total, snapshot_id.as_str(), "index.snapshot_id")?;
    text(&mut total, &profile.profile_id, "index.profile")?;
    text(&mut total, profile.digest.as_str(), "index.profile_digest")?;
    if let Some(registry_revision) = registry_revision {
        text(&mut total, registry_revision, "index.registry_revision")?;
    }
    Ok(total)
}

/// Measures each already owner-validated record separately, retaining only its
/// bounded length and carrying the checked aggregate into the next record.
pub(crate) fn measure_records(
    mut total: usize,
    projections: &[AdmittedCueBindingProjection],
    edges: &[RelationEdge],
) -> Result<(), CueContractError> {
    for projection in projections {
        projection.validate()?;
        let bytes = eliot_contracts::canonical_json_bytes(projection).map_err(|_| {
            CueContractError::Foundation {
                field: "index.projection",
            }
        })?;
        add(&mut total, bytes.len(), "index.input")?;
    }
    for edge in edges {
        edge.validate()?;
        let bytes = eliot_contracts::canonical_json_bytes(edge).map_err(|_| {
            CueContractError::Foundation {
                field: "index.edge",
            }
        })?;
        add(&mut total, bytes.len(), "index.input")?;
    }
    Ok(())
}
