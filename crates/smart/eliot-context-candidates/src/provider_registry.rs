//! The closed Context provider registry.
//!
//! The candidate denominator is a CLOSED registry of Context providers: the
//! frozen [`crate::vocabulary`] map owns what each registered provider
//! handle is, and this module owns the one question the denominator cannot
//! answer by itself: "which registered Context provider slot does this
//! contributing provider identity supply?". Keeping that resolution here
//! means the mapper resolves a contributing identity through a single owner
//! instead of re-deriving a handle at the call site.
//!
//! Two identities are distinguished and never conflated:
//!
//! - the **contributing provider identity** is the identity a provider
//!   frames its own contribution with (for the epistemic slot, the label the
//!   `smart.epistemic.context_provider` cell enforces in its `PROVIDER_LABEL`);
//! - the **registered provider handle** is the closed Context handle the
//!   denominator assigns to that material (`PROVIDER_EPISTEMIC` and its
//!   role), owned by the frozen vocabulary.
//!
//! Resolution is exact: an identity that is not registered is rejected with
//! the bounded field name, never absorbed, defaulted or synthesized. The
//! registry adds no provider, no slot, no role and no value of its own; it
//! resolves the frozen set only.

#![forbid(unsafe_code)]

use eliot_context_contracts::{ContextError, ProviderRole};

use crate::vocabulary::PROVIDER_EPISTEMIC;

/// Contributing provider identity of the epistemic slot.
///
/// Taken from the owning cell's enforced provider label, never spelled here,
/// so the provider identity has exactly one source in the workspace.
const EPISTEMIC_CONTRIBUTOR: &str = eliot_epistemic_context_provider::PROVIDER_LABEL;

/// The registered Context provider slot a contributing provider supplies.
///
/// Returns the registered [`ProviderRole`] whose handle the candidate
/// denominator uses for material framed by `contributing`. A contributing
/// identity that names no registered provider is a denominator failure, not
/// a fallback to the first, nearest or default slot.
pub(crate) fn registered_slot_for(contributing: &str) -> Result<ProviderRole, ContextError> {
    for slot in crate::vocabulary::seven_slots()? {
        if contributing == slot.provider.as_str() {
            return Ok(slot);
        }
        if contributing == EPISTEMIC_CONTRIBUTOR && slot.provider.as_str() == PROVIDER_EPISTEMIC {
            return Ok(slot);
        }
    }
    Err(ContextError::InvalidField(
        "provider_registry.contributing_provider",
    ))
}
