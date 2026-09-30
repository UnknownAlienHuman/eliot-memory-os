//! Source-faithful CC-004 owner handoff for the admitted Dreamer Orientation path.
//!
//! This adapter joins the authenticated Context reconstruction owner output to
//! the existing candidate/admission readback. It carries the original
//! readbacks by borrow, takes omission records only from the native candidate
//! owner, and leaves incomplete projection members explicit.

use eliot_agent_api::RouteFingerprint;
use eliot_context_contracts::OmissionRecord;
use eliot_governor::{
    GovernorProjectionSet, OrientationProjectionOwnerInput, OrientationProjectionOwnerOutput,
    RouteScopeFingerprint, WorkScopeBindingSnapshot, bind_orientation_projections,
};
use thiserror::Error;

use crate::context_reconstruction_route::ContextReconstructionOwnerReadback;
use crate::kernel_context_read_client::ContextCompilationOwnerReadback;

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
