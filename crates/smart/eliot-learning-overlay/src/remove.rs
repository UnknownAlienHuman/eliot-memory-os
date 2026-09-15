//! Exact inverse application proving `remove(compose(base)) == base`.
//!
//! The overlay candidate never mutates its base view. Every effective change
//! pins its exact `base` value alongside an exact inverse operation, so
//! removal replays those inverses in reverse application order over the
//! proposed values and requires the restored map to equal both the pinned
//! base values and the exact base view projection. A wrong-base, tampered,
//! irreversible, or history-losing input fails instead of rebasing.

use std::collections::BTreeMap;

use eliot_learning_contracts::{
    CampaignHarnessOverlayCandidate, CampaignLearningStateView, ChangeOperation,
    LearningContractError, LearningStateViewRecipe, SlotDisposition, ValueState,
};

use crate::{OverlayError, base};

/// Effective proposed value per touched target, keyed by target text.
#[must_use]
pub fn overlay_proposed_states(
    candidate: &CampaignHarnessOverlayCandidate,
) -> BTreeMap<String, ValueState> {
    candidate
        .changes
        .iter()
        .map(|change| (change.target.as_str().to_owned(), change.proposed.clone()))
        .collect()
}

/// Exact base value per touched target, keyed by target text.
#[must_use]
pub fn overlay_base_states(
    candidate: &CampaignHarnessOverlayCandidate,
) -> BTreeMap<String, ValueState> {
    candidate
        .changes
        .iter()
        .map(|change| (change.target.as_str().to_owned(), change.base.clone()))
        .collect()
}

/// Exact inverse operations in reverse application order.
///
/// The order is the candidate's canonical application order reversed, never
/// input order. Fails closed when the order does not cover every change.
pub fn overlay_inverse_operations(
    candidate: &CampaignHarnessOverlayCandidate,
) -> Result<Vec<ChangeOperation>, OverlayError> {
    candidate.validate()?;
    let by_target: BTreeMap<&str, _> = candidate
        .changes
        .iter()
        .map(|change| (change.target.as_str(), change))
        .collect();
    if by_target.len() != candidate.changes.len() {
        return Err(OverlayError::Contract(LearningContractError::Duplicate {
            field: "overlay.changes",
        }));
    }
    let mut inverses = Vec::with_capacity(candidate.application_order.len());
    for target in candidate.application_order.iter().rev() {
        let Some(change) = by_target.get(target.as_str()) else {
            return Err(OverlayError::Contract(
                LearningContractError::ScopeMismatch {
                    field: "overlay.application_order",
                },
            ));
        };
        inverses.push(change.inverse.inverse.clone());
    }
    Ok(inverses)
}

/// Apply every exact inverse in reverse order and prove restoration of base.
///
/// Returns the restored base states keyed by target text. The restored map
/// must equal the pinned base values, and every pinned base value must match
/// the exact base view projection; otherwise the rollback is rejected as
/// wrong-base, irreversible, or history-losing.
pub fn remove_overlay(
    candidate: &CampaignHarnessOverlayCandidate,
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
) -> Result<BTreeMap<String, ValueState>, OverlayError> {
    candidate.validate()?;
    if candidate.binding != view.binding || candidate.base_view_digest != view.canonical_digest {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "overlay.view_lineage",
            },
        ));
    }
    verify_bases_against_view(candidate, view, recipe)?;
    let mut states = overlay_proposed_states(candidate);
    for inverse in overlay_inverse_operations(candidate)? {
        apply_verified_inverse(&mut states, &inverse)?;
    }
    let expected = overlay_base_states(candidate);
    if states != expected {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "overlay.rollback",
            },
        ));
    }
    Ok(states)
}

fn verify_bases_against_view(
    candidate: &CampaignHarnessOverlayCandidate,
    view: &CampaignLearningStateView,
    recipe: &LearningStateViewRecipe,
) -> Result<(), OverlayError> {
    let slots = base::slot_map_for(recipe, view)?;
    for change in &candidate.changes {
        let (spec, projection) =
            slots
                .get(change.target.as_str())
                .copied()
                .ok_or(OverlayError::Unsupported {
                    field: "change.target",
                })?;
        if projection.disposition == SlotDisposition::KnownEmpty
            && spec.declared_members.is_empty()
            && projection.members.is_empty()
            && !projection.evidence.is_empty()
        {
            if change.base.present || change.base.digest.is_some() {
                return Err(OverlayError::Contract(
                    LearningContractError::ScopeMismatch {
                        field: "change.before",
                    },
                ));
            }
        } else {
            base::current_member(spec, projection, &change.base)?;
        }
    }
    Ok(())
}

fn apply_verified_inverse(
    states: &mut BTreeMap<String, ValueState>,
    inverse: &ChangeOperation,
) -> Result<(), OverlayError> {
    let rollback = || {
        OverlayError::Contract(LearningContractError::ScopeMismatch {
            field: "overlay.rollback",
        })
    };
    match inverse {
        ChangeOperation::Add { target, after, .. } => {
            let key = target.as_str().to_owned();
            let running = states.get(&key).ok_or_else(rollback)?;
            if running.present {
                return Err(rollback());
            }
            states.insert(key, after.clone());
        }
        ChangeOperation::Remove { target, before, .. } => {
            let key = target.as_str().to_owned();
            let running = states.get(&key).ok_or_else(rollback)?;
            if running != before {
                return Err(rollback());
            }
            states.insert(
                key,
                ValueState {
                    present: false,
                    digest: None,
                },
            );
        }
        ChangeOperation::Replace {
            target,
            before,
            after,
            ..
        } => {
            let key = target.as_str().to_owned();
            let running = states.get(&key).ok_or_else(rollback)?;
            if running != before {
                return Err(rollback());
            }
            states.insert(key, after.clone());
        }
    }
    Ok(())
}
