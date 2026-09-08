use std::collections::BTreeMap;

use eliot_learning_contracts::CampaignHarnessOverlayCandidate;

use crate::{AdmittedDeltaPair, OverlayComposeInput, OverlayError, base, bounds, changes};

/// Compose one deterministic, candidate-only task-local overlay.
pub fn compose_campaign_harness_overlay(
    input: &OverlayComposeInput<'_>,
) -> Result<CampaignHarnessOverlayCandidate, OverlayError> {
    bounds::preflight(input)?;
    base::validate_base(input)?;
    validate_admission_pairs(input)?;
    let mut candidate = assemble_candidate(input, changes::collect_changes(input)?)?;
    candidate.seal()?;
    candidate.validate_against_view_and_deltas(input.view, input.deltas)?;
    Ok(candidate)
}

fn validate_admission_pairs(input: &OverlayComposeInput<'_>) -> Result<(), OverlayError> {
    let mut pairs = BTreeMap::new();
    for pair in input.admitted {
        if pairs.insert(pair.delta_id.as_str(), pair).is_some() {
            return Err(OverlayError::Conflict {
                field: "admitted.delta_id",
            });
        }
        eliot_learning_contracts::identity::validate_digest(
            &pair.canonical_digest,
            "admitted.digest",
        )?;
    }
    for delta in input.deltas {
        let Some(pair) = pairs.remove(delta.delta_id.as_str()) else {
            return Err(OverlayError::Conflict {
                field: "admitted.delta_id",
            });
        };
        if pair.canonical_digest != delta.canonical_digest {
            return Err(OverlayError::Conflict {
                field: "admitted.digest",
            });
        }
    }
    if !pairs.is_empty() {
        return Err(OverlayError::Conflict {
            field: "admitted.delta_id",
        });
    }
    Ok(())
}

fn assemble_candidate(
    input: &OverlayComposeInput<'_>,
    changes: Vec<eliot_learning_contracts::OverlayChange>,
) -> Result<CampaignHarnessOverlayCandidate, OverlayError> {
    let mut admitted: Vec<&AdmittedDeltaPair> = input.admitted.iter().collect();
    admitted.sort_by(|left, right| left.delta_id.as_str().cmp(right.delta_id.as_str()));
    let ids = admitted.iter().map(|pair| pair.delta_id.clone()).collect();
    let digests = admitted
        .iter()
        .map(|pair| pair.canonical_digest.clone())
        .collect();
    let order = changes.iter().map(|change| change.target.clone()).collect();
    let candidate = CampaignHarnessOverlayCandidate {
        binding: input.view.binding.clone(),
        overlay_id: input.overlay_id.clone(),
        base_view_digest: input.view.canonical_digest.clone(),
        parent_revision: input.parent_revision,
        admitted_delta_ids: ids,
        admitted_delta_digests: digests,
        changes,
        dependencies: Vec::new(),
        application_order: order,
        protected_surface_base_digest: input.protected_surface_base_digest.to_owned(),
        protected_surface_proposed_digest: input.protected_surface_proposed_digest.to_owned(),
        fixed_before_observation_discriminator: input
            .fixed_before_observation_discriminator
            .clone(),
        expires_at_ms: input.expires_at_ms,
        invalidated: false,
        canonical_digest: String::new(),
    };
    if candidate.changes.len() > crate::MAX_CHANGES {
        return Err(OverlayError::Bound {
            field: "candidate.changes",
        });
    }
    Ok(candidate)
}
