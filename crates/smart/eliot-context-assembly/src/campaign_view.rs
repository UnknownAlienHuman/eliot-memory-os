//! Campaign learning-state view join for Context assembly/delivery
//! (I12.24, #1862).
//!
//! I12.24 requires the delivery owner to independently recheck that the
//! immutable campaign learning-state view behind a rendered packet still binds
//! the exact compilation being rendered. The assembly cell owns that recheck:
//! it compares the owner-issued [`CampaignViewBinding`] against the very
//! binding of the admitted set it is about to project, and never trusts that
//! admission already established it.
//!
//! The recheck is per cell on purpose. Admission and delivery are separate
//! claims, and a view that bound the admission decision must still be shown to
//! bind the delivery before a single atom is rendered.
//!
//! This module sits beside the host-only learning delivery gate but is itself
//! available on every target: it compares two already-issued contract values
//! and names no Governor state, registry, or vendor type. Only the gate that
//! needs a live owner issuance stays host-only.

use eliot_context_contracts::{CampaignViewBinding, ContextBinding, ContextError};

use crate::AssemblyError;

/// Bind one assembly/delivery to the campaign view it renders under.
///
/// `binding` is the compilation binding this delivery belongs to: for
/// [`crate::assemble_active_view`] it is the admitted set's own binding, which
/// the assembly preflight already forces to equal the recipe's. Fence drift is
/// reported as [`AssemblyError::Contract`] over
/// [`ContextError::InvalidFence`] and identity drift over
/// [`ContextError::IdentityConflict`], preserving the assembly owner's typed
/// error shape. Nothing is re-derived: the view's own recorded revisions and
/// State Fence are compared, never recomputed.
pub fn check_campaign_view_for_assembly(
    campaign: &CampaignViewBinding,
    binding: &ContextBinding,
) -> Result<(), AssemblyError> {
    campaign
        .check_compilation(binding)
        .map_err(AssemblyError::Contract)
}
