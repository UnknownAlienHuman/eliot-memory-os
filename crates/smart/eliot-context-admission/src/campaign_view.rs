//! Campaign learning-state view join for Context admission (I12.24, #1862).
//!
//! I12.24 requires the admission owner to independently recheck that the
//! immutable campaign learning-state view a packet is compiled from still
//! binds this exact compilation. The admission cell owns that recheck: it
//! compares the owner-issued [`CampaignViewBinding`] against the very binding
//! its own decision is made under, and never trusts a producer, a caller, or
//! an upstream stage to have done it.
//!
//! The recheck is deliberately independent per cell. A candidate set, a
//! decision, and a delivery are separate claims about separate stages, so a
//! view that binds the candidate stage but not the admission decision must
//! still be refused here rather than inherited as already-valid.
//!
//! This module names no Governor state and no registry, so unlike
//! [`crate::learning_gate`] it needs no host-only gating: it compares two
//! already-issued contract values.

use eliot_context_contracts::{CampaignViewBinding, ContextBinding, ContextError};

/// Bind one admission decision to the campaign view it decides under.
///
/// `binding` is the exact compilation binding this admission input validates
/// against. Fence drift is reported as [`ContextError::InvalidFence`] and any
/// other identity drift as [`ContextError::IdentityConflict`], so a caller can
/// tell a stale-fence packet from a cross-compilation one without parsing
/// text. Nothing is re-derived: the view's own recorded revisions and State
/// Fence are compared, never recomputed.
pub fn check_campaign_view_for_admission(
    campaign: &CampaignViewBinding,
    binding: &ContextBinding,
) -> Result<(), ContextError> {
    campaign.check_compilation(binding)
}
