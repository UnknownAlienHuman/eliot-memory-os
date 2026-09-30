//! The campaign learning-state view join owned by the assembly cell (#1862).
//!
//! I12.24 requires the delivery owner to independently recheck that the
//! immutable campaign learning-state view behind a rendered packet still joins
//! the exact compilation being rendered. That refusal is made here, in the
//! assembly cell, so this current owner — not a legacy compiler DTO, not the
//! candidate cell and not the admission cell — decides it.
//!
//! Nothing here trusts a caller-carried verdict or another cell's outcome. Every
//! compared fact has an independent producer:
//!
//! - the State Fence, task and scope come from the admitted set's own
//!   [`ContextBinding`] — the binding the delivery actually renders under — and
//!   are compared against the immutable view's own recorded binding;
//! - the load-bearing Context recipe revision is compared against
//!   `context_recipe_body_digest`, which the Context owner re-derived from the
//!   exact recipe body its own publication validator accepted — not against the
//!   view's own record of itself.
//!
//! A stale, missing, blocked or invalidated view therefore fails here, before a
//! single atom is rendered.
//!
//! ## Independence from the candidate and admission cells
//!
//! `eliot_context_candidates::check_campaign_learning_state_view` and
//! `eliot_context_admission::check_campaign_view_for_admission` perform the
//! same class of join for their own stages. That is deliberate, not a second
//! scheme: candidate, admission and delivery are separate claims about separate
//! stages, so each cell re-derives the join from the binding *it* owns. This
//! cell binds the view to the admitted set, which is the only binding that
//! describes what is about to be rendered. No cell inherits another's verdict.

use eliot_context_contracts::{AdmittedContextSet, ContextError};
use eliot_contracts::fences_match_exact;
use eliot_learning_contracts::{
    CampaignLearningStateView, CampaignSourceResolutionStatus, CampaignSourceRole, Completeness,
};

use crate::AssemblyError;

/// Bind one published immutable campaign learning-state view to one delivery,
/// refusing a view that does not join the compilation being rendered.
///
/// `admitted` is the exact admitted set about to be projected; its own binding
/// is the binding this delivery renders under. Every refusal is projected onto
/// [`AssemblyError::Contract`] over the exact [`ContextError`], so the
/// assembly owner's typed error shape survives the boundary and a
/// stale-fence view stays distinguishable from a cross-compilation one.
///
/// Typed refusals, in the order they are decided:
///
/// - a view whose recorded State Fence does not fence-match the admitted
///   set's is [`ContextError::InvalidFence`] — the I12.26 packet-refresh arm;
/// - a task or scope disagreement is [`ContextError::IdentityConflict`];
/// - an invalidated view, or one whose completeness is `STALE` or `BLOCKED`,
///   is `InvalidField("campaign_view.completeness")`;
/// - a Context-owned row read under another fence is
///   [`ContextError::InvalidFence`];
/// - an absent or non-current Context recipe row, or a resolved Context row
///   with no reference, is `MissingField("campaign_view.context_recipe")` /
///   `MissingField("campaign_view.context_reference")`;
/// - a Context recipe row whose recorded content digest is not the digest the
///   Context owner re-derived is
///   `InvalidDigest("campaign_view.context_recipe")`.
///
/// The `Partial` completeness state is not refused here: the learning-state
/// owner already admits it only when every omitted field is recorded as
/// non-load-bearing for the bound recipe, and this join adds nothing to that
/// decision.
pub fn check_campaign_view_for_assembly(
    admitted: &AdmittedContextSet,
    view: &CampaignLearningStateView,
    context_recipe_body_digest: &str,
) -> Result<(), AssemblyError> {
    let binding = &admitted.binding;
    binding.validate().map_err(AssemblyError::Contract)?;
    if !fences_match_exact(&view.binding.state_fence, &binding.state_fence) {
        return Err(AssemblyError::Contract(ContextError::InvalidFence));
    }
    if view.binding.task_id != binding.task_id || view.binding.scope != binding.scope_id {
        return Err(AssemblyError::Contract(ContextError::IdentityConflict));
    }
    if view.invalidated
        || matches!(
            view.completeness,
            Completeness::Stale | Completeness::Blocked
        )
    {
        return Err(AssemblyError::Contract(ContextError::InvalidField(
            "campaign_view.completeness",
        )));
    }
    let mut context_recipe_digest = None;
    for resolution in &view.provenance.source_resolutions {
        if !is_context_owned(resolution.role) {
            continue;
        }
        if !fences_match_exact(&resolution.read_state_fence, &binding.state_fence) {
            return Err(AssemblyError::Contract(ContextError::InvalidFence));
        }
        if resolution.role == CampaignSourceRole::ContextRecipe {
            if resolution.status != CampaignSourceResolutionStatus::Current {
                return Err(AssemblyError::Contract(ContextError::MissingField(
                    "campaign_view.context_recipe",
                )));
            }
            context_recipe_digest = Some(
                resolution
                    .reference
                    .as_ref()
                    .ok_or(AssemblyError::Contract(ContextError::MissingField(
                        "campaign_view.context_recipe",
                    )))?
                    .content_digest
                    .clone(),
            );
        } else if resolution.status == CampaignSourceResolutionStatus::Current
            && resolution.reference.is_none()
        {
            return Err(AssemblyError::Contract(ContextError::MissingField(
                "campaign_view.context_reference",
            )));
        }
    }
    let context_recipe_digest = context_recipe_digest.ok_or(AssemblyError::Contract(
        ContextError::MissingField("campaign_view.context_recipe"),
    ))?;
    if context_recipe_digest != context_recipe_body_digest {
        return Err(AssemblyError::Contract(ContextError::InvalidDigest(
            "campaign_view.context_recipe",
        )));
    }
    Ok(())
}

/// Whether the campaign source role belongs to the Context owner.
fn is_context_owned(role: CampaignSourceRole) -> bool {
    matches!(
        role,
        CampaignSourceRole::ContextRecipe
            | CampaignSourceRole::ContextToolPolicy
            | CampaignSourceRole::ContextDelivery
    )
}
