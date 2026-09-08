use std::collections::BTreeMap;

use eliot_evidence::EvidenceFreshness;
use eliot_learning_contracts::{Completeness, LearningContractError, SlotDisposition};

use crate::{OverlayComposeInput, OverlayError};

pub(crate) fn validate_base(input: &OverlayComposeInput<'_>) -> Result<(), OverlayError> {
    input.recipe.validate()?;
    input.view.validate_against(input.recipe)?;
    if input.view.invalidated
        || !matches!(
            input.view.completeness,
            Completeness::CompleteForDeclaredRecipe
        )
        || !input.view.omissions.is_empty()
        || !input.view.frontier.is_empty()
        || !input.view.owner_disagreements.is_empty()
    {
        return Err(OverlayError::Unsupported {
            field: "view.completeness",
        });
    }
    if !matches!(
        input.recipe.freshness,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    ) {
        return Err(OverlayError::Unsupported {
            field: "recipe.freshness",
        });
    }
    if input.view.binding.state_fence.policy_revision != Some(input.view.binding.policy_revision) {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "binding.policy_revision",
            },
        ));
    }
    if input.view.slots.iter().any(|slot| {
        !matches!(
            slot.disposition,
            SlotDisposition::Current | SlotDisposition::KnownEmpty
        ) || (slot.disposition == SlotDisposition::KnownEmpty && slot.evidence.is_empty())
            || slot.members.iter().any(|member| {
                member.disposition != SlotDisposition::Current
                    && member.disposition != SlotDisposition::KnownEmpty
            })
    }) {
        return Err(OverlayError::Unsupported {
            field: "view.slot_disposition",
        });
    }
    validate_shared_lineage(input.view)?;
    let Some(parent) = input.view.binding.state_fence.task_revision else {
        return Err(OverlayError::Contract(LearningContractError::Missing {
            field: "parent_revision",
        }));
    };
    if parent != input.parent_revision {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "parent_revision",
            },
        ));
    }
    if input.expires_at_ms == 0 || input.expires_at_ms <= input.observed_at_ms {
        return Err(OverlayError::Expired);
    }
    if input.protected_surface_base_digest != input.protected_surface_proposed_digest {
        return Err(OverlayError::ProtectedSurfaceChanged);
    }
    if input.protected_surface_base_digest.len() != 64
        || input
            .protected_surface_base_digest
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(OverlayError::Contract(
            LearningContractError::InvalidDigest {
                field: "protected_surface",
            },
        ));
    }
    Ok(())
}

fn validate_shared_lineage(
    view: &eliot_learning_contracts::CampaignLearningStateView,
) -> Result<(), OverlayError> {
    let mut by_source = BTreeMap::new();
    for slot in &view.slots {
        for member in &slot.members {
            let key = (
                member.source.owner.as_str(),
                member.source.snapshot.as_str(),
            );
            if let Some(previous) = by_source.insert(key, &member.source)
                && previous != &member.source
            {
                return Err(OverlayError::Contract(
                    LearningContractError::ScopeMismatch {
                        field: "view.source_lineage",
                    },
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn slot_map<'a>(
    input: &'a OverlayComposeInput<'_>,
) -> Result<
    BTreeMap<
        &'a str,
        (
            &'a eliot_learning_contracts::SlotSpec,
            &'a eliot_learning_contracts::SlotProjection,
        ),
    >,
    OverlayError,
> {
    let projections: BTreeMap<_, _> = input
        .view
        .slots
        .iter()
        .map(|slot| (slot.slot_id.as_str(), slot))
        .collect();
    let mut map = BTreeMap::new();
    for spec in &input.recipe.slots {
        let projection =
            projections
                .get(spec.slot_id.as_str())
                .copied()
                .ok_or(OverlayError::Unsupported {
                    field: "slot.projection",
                })?;
        if map
            .insert(spec.target.as_str(), (spec, projection))
            .is_some()
        {
            return Err(OverlayError::Conflict {
                field: "slot.target",
            });
        }
    }
    Ok(map)
}

pub(crate) fn current_member<'a>(
    spec: &eliot_learning_contracts::SlotSpec,
    projection: &'a eliot_learning_contracts::SlotProjection,
    before: &eliot_learning_contracts::ValueState,
) -> Result<&'a eliot_learning_contracts::MemberProjection, OverlayError> {
    if projection.disposition != SlotDisposition::Current
        || spec.declared_members.len() != 1
        || projection.members.len() != 1
    {
        return Err(OverlayError::Unsupported {
            field: "slot.current_member",
        });
    }
    let member = &projection.members[0];
    if member.member_id != spec.declared_members[0]
        || member.owner != spec.owner
        || member.disposition != SlotDisposition::Current
        || member.value_digest.as_deref() != before.digest.as_deref()
    {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "change.before",
            },
        ));
    }
    Ok(member)
}
