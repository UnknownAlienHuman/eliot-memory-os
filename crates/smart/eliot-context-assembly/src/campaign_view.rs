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
//!
//! [`check_campaign_view_for_delivery`] is the same cell's delivery-stage join
//! against the delivery owner record the live campaign route actually holds. It
//! exists because an `AdmittedContextSet` is the one owner record this tree
//! cannot yet produce there, and a join no production caller can reach is not
//! ownership; it is a second entry point over the *same* delivery-boundary
//! claim, not a second scheme, and both bind the view to a delivery owner
//! record rather than to a caller-carried verdict.

use eliot_context_contracts::{
    AdmittedContextSet, ContextError, SessionDeliverySnapshot, canonical_json_serializer_identity,
};
use eliot_contracts::{StateFence, fences_match_exact};
use eliot_learning_contracts::{
    CampaignLearningStateView, CampaignOwnerRecordId, CampaignOwnerRevision,
    CampaignSourceResolutionStatus, CampaignSourceRole, Completeness,
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

/// Bind one published immutable campaign learning-state view to the delivery
/// this packet publishes, refusing a view that does not join it.
///
/// This is the delivery-stage owner join, and it is the one the live campaign
/// route reaches. [`check_campaign_view_for_assembly`] binds the view to an
/// `AdmittedContextSet`, and an admitted set is the one owner record this tree
/// cannot yet produce on that route — the owner-minted admission closure is
/// reported absent rather than fabricated (see
/// `CampaignPacketGapCode::AdmissionClosureUnbound`). The delivery this route
/// actually performs is the published packet itself, and its delivery owner
/// record is the Context owner's own `ContextDelivery` row: the prior
/// `SessionDeliverySnapshot` the delivery owner published for this attempt,
/// read through an authenticated named read and re-derived by the owner's own
/// publication validator before this call.
///
/// Every compared fact therefore has an independent producer:
///
/// - `packet_state_fence` is the admitted packet's own retained Kernel fence,
///   and the view's `ContextDelivery` row is refused unless it was read under
///   that fence. A delivery row carried over from another attempt's read is
///   `InvalidFence`, never a silent accept;
/// - `delivery` is the delivery owner's own record, so the task and scope the
///   delivery is bound to are compared against the view's own binding and the
///   delivery owner row identity the view froze — its owner-native record id
///   and revision, which the delivery owner mints from the snapshot's own
///   `source_id` and `snapshot_revision` — is compared against the same
///   snapshot. A view that names a different delivery revision, or a fence the
///   delivery record does not itself carry, is refused rather than rendered;
/// - when `delivery` is `None` the delivery owner published no row for this
///   packet, and a view that nevertheless freezes a `CURRENT` `ContextDelivery`
///   reference is refused: an absent delivery owner record is never filled from
///   the bytes of some other one.
///
/// The delivery snapshot's own `state_fence` is deliberately NOT compared with
/// `packet_state_fence`. `context_delivery_publication` preserves the prior
/// delivery's original attempt and fence verbatim — a later recipe may belong to
/// a later attempt and fence — so requiring equality here would refuse every
/// real delivery. The fence this cell does enforce is the read fence on the
/// view's row and the fence the delivery record itself carries.
///
/// `STALE` and `BLOCKED` are refused here for the same reason they are refused
/// by the other cells: they are never filled from a convenient current file.
/// `Partial` is not refused here; the learning-state owner already admits it
/// only when every omitted field is recorded as non-load-bearing for the bound
/// recipe.
pub fn check_campaign_view_for_delivery(
    view: &CampaignLearningStateView,
    packet_state_fence: &StateFence,
    delivery: Option<&SessionDeliverySnapshot>,
) -> Result<(), AssemblyError> {
    packet_state_fence
        .validate()
        .map_err(|_| AssemblyError::Contract(ContextError::InvalidFence))?;
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
    let row = view
        .provenance
        .source_resolutions
        .iter()
        .find(|resolution| resolution.role == CampaignSourceRole::ContextDelivery);
    let Some(delivery) = delivery else {
        if row.is_some_and(|row| {
            row.status == CampaignSourceResolutionStatus::Current && row.reference.is_some()
        }) {
            return Err(AssemblyError::Contract(ContextError::MissingField(
                "campaign_view.context_delivery",
            )));
        }
        return Ok(());
    };
    let row = row.ok_or(AssemblyError::Contract(ContextError::MissingField(
        "campaign_view.context_delivery",
    )))?;
    if row.status != CampaignSourceResolutionStatus::Current {
        return Err(AssemblyError::Contract(ContextError::MissingField(
            "campaign_view.context_delivery",
        )));
    }
    let reference =
        row.reference
            .as_ref()
            .ok_or(AssemblyError::Contract(ContextError::MissingField(
                "campaign_view.context_delivery",
            )))?;
    if !fences_match_exact(&row.read_state_fence, packet_state_fence) {
        return Err(AssemblyError::Contract(ContextError::InvalidFence));
    }
    if delivery.task_id != view.binding.task_id || delivery.scope_id != view.binding.scope {
        return Err(AssemblyError::Contract(ContextError::IdentityConflict));
    }
    if !fences_match_exact(&reference.recorded_state_fence, &delivery.state_fence) {
        return Err(AssemblyError::Contract(ContextError::InvalidFence));
    }
    if reference.record_id
        != CampaignOwnerRecordId::Resource(delivery.source_id.as_str().to_owned())
        || reference.revision
            != CampaignOwnerRevision::ResourceSnapshot(delivery.snapshot_revision.clone())
    {
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
