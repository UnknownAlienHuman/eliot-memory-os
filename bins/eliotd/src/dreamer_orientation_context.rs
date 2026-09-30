//! Source-faithful CC-004 owner handoff for the admitted Dreamer Orientation path.
//!
//! This adapter joins the authenticated Context reconstruction owner output to
//! the existing candidate/admission readback. It carries the original
//! readbacks by borrow, takes omission records only from the native candidate
//! owner, and leaves incomplete projection members explicit.

use eliot_agent_api::RouteFingerprint;
use eliot_context::campaign_publication::{
    ContextPublicationError, context_recipe_body_digest,
};
use eliot_context_contracts::OmissionRecord;
use eliot_governor::{
    GovernorProjectionSet, OrientationProjectionOwnerInput, OrientationProjectionOwnerOutput,
    RouteScopeFingerprint, WorkScopeBindingSnapshot, bind_orientation_projections,
};
use thiserror::Error;

use crate::context_reconstruction_route::ContextReconstructionOwnerReadback;
use crate::kernel_context_read_client::{
    ContextCompilationOwnerOutcome, ContextCompilationOwnerReadback, KernelContextReadClient,
    PacketCompositionError,
};

/// Typed failure when the compiler result is not joined to the original
/// authenticated Context reconstruction closure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DreamerOrientationContextError {
    /// The candidate, admission input or decision changed the original binding.
    #[error("candidate/admission context binding differs from the authenticated Context owner")]
    BindingMismatch,
    /// The compiler consumed a different SevenRoleInputs object.
    #[error("candidate/admission owner did not consume the original SevenRoleInputs object")]
    RoleSourceMismatch,
}

/// Typed refusal when original owner suppliers or the campaign view do not
/// bind to this authenticated Context reconstruction.
#[derive(Debug, Error)]
pub enum DreamerOrientationCompilationError {
    /// This legacy owner source has no native compiler supplier profile.
    #[error("authenticated Context owner source has no compiler supplier profile")]
    MissingSuppliers,
    /// The recipe and independent tool-policy readbacks do not retain the same
    /// current supplier profile and source identity.
    #[error("Context compiler suppliers are not bound by both owner readbacks")]
    SupplierReadbackMismatch,
    /// The stored recipe row has no owner content identity.
    #[error("authenticated ContextRecipe readback has no stored source body")]
    MissingRecipeSource,
    /// The profile's exact campaign view was not retained from its named read.
    #[error("authenticated compiler profile has no current campaign learning-state view")]
    MissingCampaignLearningView,
    /// The typed recipe body differs from its exact stored owner content.
    #[error("authenticated ContextRecipe body does not match its owner content identity")]
    RecipeDigestMismatch,
    /// The campaign learning-state view join refused the compilation.
    #[error("native Context packet compilation refused: {0}")]
    Composition(#[from] PacketCompositionError),
    /// The original typed Context owner profile failed its source validation.
    #[error("Context compiler supplier profile is invalid: {0}")]
    SupplierValidation(#[from] ContextPublicationError),
}

/// Exact owner lineage and CC-004 member join for one Orientation operation.
///
/// The full readback values remain available beside the bounded projections so
/// the caller can bind packet provenance to the original named reads and native
/// compiler decisions rather than projected strings alone.
pub struct DreamerOrientationContextOwnerReadback<'owner, 'source> {
    /// Authenticated query, original source recipe reads, request and role reads.
    pub reconstruction: &'owner ContextReconstructionOwnerReadback<'source>,
    /// Original candidate/admission/assembly owner outputs, including typed gaps.
    pub compilation: &'owner ContextCompilationOwnerReadback<'owner>,
    /// CC-004 set when complete, with exact per-member dispositions always kept.
    pub projections: OrientationProjectionOwnerOutput<'owner>,
}

/// Invoke the real candidate, admission and assembly owner chain from the
/// exact Context reconstruction and current owner suppliers retained before
/// model execution. No suppliers are synthesized from reconstructed roles.
pub fn compile_dreamer_orientation_context<'owner, 'source>(
    reconstruction: &'owner ContextReconstructionOwnerReadback<'source>,
) -> Result<ContextCompilationOwnerReadback<'owner>, DreamerOrientationCompilationError> {
    let Some(suppliers) = reconstruction.context_recipe.body.compiler_suppliers.as_ref() else {
        return Err(DreamerOrientationCompilationError::MissingSuppliers);
    };
    let Some(tool_policy) = reconstruction.context_tool_policy.as_ref() else {
        return Err(DreamerOrientationCompilationError::SupplierReadbackMismatch);
    };
    if tool_policy.compiler_suppliers.as_ref() != Some(suppliers)
        || tool_policy.read.validate().is_err()
        || tool_policy.read.status != eliot_store_api::CampaignSourceReadStatus::Current
        || tool_policy.read.read_state_fence != reconstruction.source_envelope.state_fence
        || reconstruction.context_recipe.read.validate().is_err()
        || reconstruction.context_recipe.read.status
            != eliot_store_api::CampaignSourceReadStatus::Current
        || reconstruction.context_recipe.read.read_state_fence
            != reconstruction.source_envelope.state_fence
    {
        return Err(DreamerOrientationCompilationError::SupplierReadbackMismatch);
    }
    suppliers.validate_for_recipe(&reconstruction.context_recipe.body.recipe)?;
    let source = reconstruction
        .context_recipe
        .read
        .source
        .as_ref()
        .ok_or(DreamerOrientationCompilationError::MissingRecipeSource)?;
    let rederived_digest = context_recipe_body_digest(&reconstruction.context_recipe.body)?;
    if rederived_digest != source.content_digest {
        return Err(DreamerOrientationCompilationError::RecipeDigestMismatch);
    }
    let campaign_learning_view = reconstruction
        .campaign_learning_view
        .as_ref()
        .ok_or(DreamerOrientationCompilationError::MissingCampaignLearningView)?;
    let campaign_view = campaign_learning_view
        .read
        .publication
        .as_ref()
        .filter(|publication| {
            publication.view_id == suppliers.campaign_learning_state_view_id
                && publication.state_fence == reconstruction.source_envelope.state_fence
        })
        .map(|publication| &publication.view)
        .ok_or(DreamerOrientationCompilationError::MissingCampaignLearningView)?;

    let admission = &suppliers.admission_parts;
    KernelContextReadClient::compile_context_packet(
        &reconstruction.seven_role_inputs,
        &suppliers.candidate_request,
        &reconstruction.context_recipe.body.recipe,
        &suppliers.candidate_policy,
        campaign_view,
        &source.content_digest,
        admission.floor.clone(),
        admission.priority.clone(),
        admission.rule.clone(),
        admission.measurement_profile.clone(),
        admission.supplied_omissions.clone(),
        admission.measurements.clone(),
        suppliers.quality_scorecard.clone(),
        &suppliers.assembly_policy,
        |payload| suppliers.measure(payload),
    )
    .map_err(DreamerOrientationCompilationError::from)
}

/// Serializes the complete native owner readback carried by the result-body
/// transport. Original request, role reads, candidate omissions, admission
/// result, rank traces, assembly disposition and original owner policies stay
/// together; only an assembly-stage refusal remains an error result.
pub(crate) fn compilation_owner_publication(
    compilation: &ContextCompilationOwnerReadback<'_>,
) -> Result<serde_json::Value, String> {
    let outcome = match &compilation.outcome {
        ContextCompilationOwnerOutcome::Complete(assembled) => {
            serde_json::json!({"complete": assembled})
        }
        ContextCompilationOwnerOutcome::Incomplete(gaps) => {
            serde_json::json!({"incomplete": gaps})
        }
        ContextCompilationOwnerOutcome::Refused(error) => return Err(error.to_string()),
    };
    serde_json::to_value(serde_json::json!({
        "request": compilation.request,
        "recipe": compilation.recipe,
        "candidate_policy": compilation.candidate_policy,
        "assembly_policy": compilation.assembly_policy,
        "role_inputs": compilation.role_inputs,
        "quality": compilation.quality,
        "candidates": compilation.candidates,
        "admission_input": compilation.admission_input,
        "admission": compilation.admission,
        "rank_trace_delivery": compilation.rank_trace_delivery,
        "outcome": outcome,
    }))
    .map_err(|error| error.to_string())
}

/// Binds the CC-004 projections to the exact Context reconstruction and native
/// compiler owner output used by this Orientation operation.
///
/// Caller-owned Governor and capability source values must come from the
/// current admitted operation. Optional route inputs stay absent when the
/// admission owner did not retain them; they are never inferred from projected
/// text or model-only summaries.
pub fn bind_dreamer_orientation_context<'owner, 'source>(
    reconstruction: &'owner ContextReconstructionOwnerReadback<'source>,
    compilation: &'owner ContextCompilationOwnerReadback<'owner>,
    governor: &'owner GovernorProjectionSet,
    work_scope: &'owner WorkScopeBindingSnapshot,
    original_route: Option<&'owner RouteFingerprint>,
    current_route_scope: Option<&'owner RouteScopeFingerprint>,
    capability_now: Option<u64>,
) -> Result<DreamerOrientationContextOwnerReadback<'owner, 'source>, DreamerOrientationContextError>
{
    let binding = reconstruction.binding();
    if compilation.recipe != &reconstruction.context_recipe.body.recipe
        || compilation.request.binding != *binding
        || compilation.candidates.set.binding != *binding
        || compilation.admission_input.binding != *binding
        || compilation.admission.binding != *binding
    {
        return Err(DreamerOrientationContextError::BindingMismatch);
    }
    if !std::ptr::eq(compilation.role_inputs, &reconstruction.seven_role_inputs) {
        return Err(DreamerOrientationContextError::RoleSourceMismatch);
    }

    let source_omissions: &[OmissionRecord] = compilation.candidates.omissions.as_slice();
    let projections = bind_orientation_projections(&OrientationProjectionOwnerInput {
        binding,
        governor,
        work_scope,
        role_inputs: &reconstruction.seven_role_inputs,
        context_request: &reconstruction.request,
        omissions: Some(source_omissions),
        original_route,
        current_route_scope,
        capability_now,
    });

    Ok(DreamerOrientationContextOwnerReadback {
        reconstruction,
        compilation,
        projections,
    })
}
