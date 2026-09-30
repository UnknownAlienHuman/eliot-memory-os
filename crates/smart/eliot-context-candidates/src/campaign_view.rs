//! The campaign learning-state view join owned by the candidate cell (#1862).
//!
//! I12.24 requires the Context stage that compiles the next materially
//! comparable attempt to refuse a campaign view whose load-bearing owner
//! revisions or State Fence do not join *this* compilation. That refusal is
//! made here, in the candidate cell, so it is the current owner and not a
//! legacy compiler DTO that decides.
//!
//! Nothing here trusts a caller-carried verdict. Every compared fact has an
//! independent producer:
//!
//! - the State Fence, task, scope and request identities come from the
//!   [`CandidateRequest`] the route minted from the Kernel-admitted
//!   invocation, and are compared against the immutable view's own recorded
//!   binding;
//! - the load-bearing Context recipe revision is compared against
//!   `context_recipe_body_digest`, which the Context owner re-derived from the
//!   exact recipe body its own publication validator accepted — not against
//!   the view's own record of itself.
//!
//! A stale, missing, blocked or invalidated view therefore fails here, and no
//! legacy-only helper downstream can accept a view this cell refused.
//!
//! ## Scope
//!
//! I12.24 groups `context_compiler_recipe_tool_surface_and_delivery_revision`
//! as one load-bearing source group, but only the recipe row can bind the
//! candidate stage: it is the policy this stage compiles under. The
//! tool-policy and delivery rows are checked for fence agreement and for
//! carrying a reference whenever they are resolved, and may stay explicitly
//! absent exactly as the task manifest declares. The admission and assembly
//! cells enforce their own joins on the material they actually hold; this join
//! does not stand in for them.

use eliot_context_contracts::{ContextError, ContextRecipe};
use eliot_contracts::fences_match_exact;
use eliot_learning_contracts::{
    CampaignLearningStateView, CampaignSourceResolutionStatus, CampaignSourceRole, Completeness,
    ContractBinding,
};

use crate::CandidateRequest;

/// Bind one published immutable campaign learning-state view to one candidate
/// request, refusing a view that does not join this compilation.
///
/// Typed refusals, in the order they are decided:
///
/// - a request or recipe that fails its own contract validation propagates
///   that error unchanged;
/// - a recipe bound to a different request, or a view whose recorded State
///   Fence does not fence-match the request's, is [`ContextError::InvalidFence`]
///   — the I12.26 packet-refresh arm;
/// - a task, scope or request-identity disagreement is
///   [`ContextError::IdentityConflict`];
/// - an invalidated view, or one whose completeness is `STALE` or `BLOCKED`,
///   is `InvalidField("campaign_view.completeness")`;
/// - a Context-owned row read under another fence is
///   [`ContextError::InvalidFence`];
/// - an absent or non-current Context recipe row, or a resolved Context row
///   with no reference, is `MissingField("campaign_view.context_recipe")` /
///   `MissingField("campaign_view.context_reference")`;
/// - a Context recipe row whose recorded content digest is not the digest the
///   Context owner re-derived is `InvalidDigest("campaign_view.context_recipe")`.
///
/// The `Partial` completeness state is not refused here: the learning-state
/// owner already admits it only when every omitted field is recorded as
/// non-load-bearing for the bound recipe, and this join adds nothing to that
/// decision.
pub fn check_campaign_learning_state_view(
    request: &CandidateRequest,
    recipe: &ContextRecipe,
    view: &CampaignLearningStateView,
    context_recipe_body_digest: &str,
) -> Result<(), ContextError> {
    request.validate()?;
    recipe.validate()?;
    if recipe.binding != request.binding {
        return Err(ContextError::InvalidFence);
    }
    check_compilation_identity(&view.binding, request)?;
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
        if !fences_match_exact(&resolution.read_state_fence, &request.binding.state_fence) {
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

/// Join the view's recorded compilation identity to this request's.
fn check_compilation_identity(
    binding: &ContractBinding,
    request: &CandidateRequest,
) -> Result<(), ContextError> {
    if !fences_match_exact(&binding.state_fence, &request.binding.state_fence) {
        return Err(ContextError::InvalidFence);
    }
    if binding.task_id != request.binding.task_id
        || binding.scope != request.binding.scope_id
        || binding.request_id != request.request_id
    {
        return Err(ContextError::IdentityConflict);
    }
    Ok(())
}
