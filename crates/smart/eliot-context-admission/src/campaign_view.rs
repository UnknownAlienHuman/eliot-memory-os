//! The campaign learning-state view join owned by the admission cell (#1862).
//!
//! I12.24 requires the admission owner to independently recheck that the
//! immutable campaign learning-state view behind a decision still joins the
//! exact compilation that decision is made under. That refusal is made here,
//! in the admission cell, so this current owner — not a legacy compiler DTO
//! and not the candidate cell — decides it.
//!
//! Nothing here trusts a caller-carried verdict or another cell's outcome. Every
//! compared fact has an independent producer:
//!
//! - the State Fence, task and scope come from [`ContextBinding`], the exact
//!   binding the admission decision itself is made under, and are compared
//!   against the immutable view's own recorded binding;
//! - the load-bearing Context recipe revision is compared against
//!   `context_recipe_body_digest`, which the Context owner re-derived from the
//!   exact recipe body its own publication validator accepted — not against the
//!   view's own record of itself.
//!
//! A stale, missing, blocked or invalidated view therefore fails here, and
//! nothing downstream can accept a view this cell refused.
//!
//! ## Independence from the candidate cell
//!
//! `eliot_context_candidates::check_campaign_learning_state_view` performs the
//! same class of join for the candidate stage. That duplication is deliberate
//! and is not a second scheme: candidate, admission and delivery are separate
//! claims about separate stages, so each cell re-derives the join from the
//! binding *it* owns. Admission binds the view to the decision binding;
//! assembly binds it to the admitted set's own binding. No cell inherits
//! another's verdict, and skipping any one of them refuses nothing in the
//! others.

use eliot_context_contracts::{ContextBinding, ContextError};
use eliot_contracts::fences_match_exact;
use eliot_learning_contracts::{
    CampaignLearningStateView, CampaignSourceResolutionStatus, CampaignSourceRole, Completeness,
};

/// Bind one published immutable campaign learning-state view to one admission
/// decision, refusing a view that does not join this compilation.
///
/// `binding` is the exact binding this admission decision is made under — the
/// same value `AdmissionInput::validate` forces equal to its own binding, its
/// recipe binding, and its floor binding. It is the admission cell's own
/// fact, not a value forwarded from the candidate stage.
///
/// Typed refusals, in the order they are decided:
///
/// - a view whose recorded State Fence does not fence-match the decision's is
///   [`ContextError::InvalidFence`] — the I12.26 packet-refresh arm;
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
pub fn check_campaign_view_for_admission(
    binding: &ContextBinding,
    view: &CampaignLearningStateView,
    context_recipe_body_digest: &str,
) -> Result<(), ContextError> {
    binding.validate()?;
    if !fences_match_exact(&view.binding.state_fence, &binding.state_fence) {
        return Err(ContextError::InvalidFence);
    }
    if view.binding.task_id != binding.task_id || view.binding.scope != binding.scope_id {
        return Err(ContextError::IdentityConflict);
    }
    if view.invalidated
        || matches!(
            view.completeness,
            Completeness::Stale | Completeness::Blocked
        )
    {
        return Err(ContextError::InvalidField("campaign_view.completeness"));
    }
    let mut context_recipe_reference = None;
    for resolution in &view.provenance.source_resolutions {
        if !is_context_owned(resolution.role) {
            continue;
        }
        if !fences_match_exact(&resolution.read_state_fence, &binding.state_fence) {
            return Err(ContextError::InvalidFence);
        }
        if resolution.role == CampaignSourceRole::ContextRecipe {
            if resolution.status != CampaignSourceResolutionStatus::Current {
                return Err(ContextError::MissingField("campaign_view.context_recipe"));
            }
            context_recipe_reference = Some(
                resolution
                    .reference
                    .as_ref()
                    .ok_or(ContextError::MissingField("campaign_view.context_recipe"))?,
            );
        } else if resolution.status == CampaignSourceResolutionStatus::Current
            && resolution.reference.is_none()
        {
            return Err(ContextError::MissingField(
                "campaign_view.context_reference",
            ));
        }
    }
    let reference = context_recipe_reference
        .ok_or(ContextError::MissingField("campaign_view.context_recipe"))?;
    if reference.content_digest != context_recipe_body_digest {
        return Err(ContextError::InvalidDigest("campaign_view.context_recipe"));
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
