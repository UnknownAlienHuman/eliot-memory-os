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

use eliot_context_contracts::{
    AdmittedContextSet, ContextError, canonical_json_serializer_identity,
};
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
///   `InvalidDigest("campaign_view.context_recipe")`;
/// - an admitted set whose recorded measurement serializer is not the
///   owner-published canonical Context codec identity is
///   `IdentityConflict` (see the envelope-codec join below).
///
/// The `Partial` completeness state is not refused here: the learning-state
/// owner already admits it only when every omitted field is recorded as
/// non-load-bearing for the bound recipe, and this join adds nothing to that
/// decision.
///
/// ## Envelope-codec identity (#1862, I2.16)
///
/// I2.16 requires a measurement to name the serializer identity, version and
/// options of the codec that produced the bytes it digested, and refuses to
/// certify a measurement taken under a changed serializer. Nothing named a
/// publisher for those values on this lane, so the three consumer chains the
/// Context lane has — the candidate member binding, the admission measurement
/// closure and the assembly measurement verification — could only ever compare
/// one caller's labels against another caller's labels.
///
/// This join is where the owner value reaches a real campaign-lane record. The
/// admitted set carries its own serializer identity in
/// `ContextEconomyReceipt::measurement` (`MeasurementRef`), which
/// `ContextEconomyReceipt::validate` already checks, and it is compared here
/// against [`canonical_json_serializer_identity`], the measurement owner's
/// publication of the codec this lane serializes with. The admitted set is the
/// last owner record that exists before rendering, so a set admitted under a
/// foreign envelope codec is refused here rather than rendered and graded.
///
/// `MeasurementRef` carries only the serializer identity, not the version and
/// options pair; those two live on `SerializedContextMeasurement` and on
/// `QualityOutputBinding`, neither of which this join receives. The version and
/// options pair therefore stays where it already is compared — the whole triple
/// against `AssemblyPolicy` in `crate::measurement::verify` — and is not
/// claimed here.
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
    // The admitted set's recorded envelope-codec identity against the owner
    // publication. The recorded value is validated in shape by the receipt's own
    // `validate`; the owner comparison is made here, and a foreign identity is
    // an identity conflict rather than a silently rendered packet.
    let owner_serializer = canonical_json_serializer_identity();
    if admitted.economy.measurement.serializer != owner_serializer.serializer_id {
        return Err(AssemblyError::Contract(ContextError::IdentityConflict));
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
