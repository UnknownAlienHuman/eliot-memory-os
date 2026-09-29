//! The closed Context provider registry (#238).
//!
//! The candidate denominator is a CLOSED registry of Context providers: the
//! frozen [`crate::vocabulary`] map owns what each registered provider
//! handle is, and this module owns the question "which registered Context
//! provider slot does this contributing provider identity supply?". Keeping
//! that lookup here means the mapper, the denominator checks and the
//! migration target all resolve provider identity through one owner instead
//! of re-deriving handles at each call site.
//!
//! Two identities are distinguished and never conflated:
//!
//! - the **contributing provider identity** is the identity a provider
//!   frames its own contribution with (for the epistemic slot, the label the
//!   `smart.epistemic.context_provider` cell enforces in
//!   `PROVIDER_LABEL`);
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

/// The closed registered Context provider set, in canonical emission order.
///
/// Same seven slots, same order, same roles as
/// [`crate::vocabulary::seven_slots`]; this is the single call site the
/// mapper and the denominator checks resolve the registered set through.
pub(crate) fn registered_providers() -> Result<Vec<ProviderRole>, ContextError> {
    crate::vocabulary::seven_slots()
}

/// The registered Context provider slot a contributing provider supplies.
///
/// Returns the registered [`ProviderRole`] whose handle the candidate
/// denominator uses for material framed by `contributing`. A contributing
/// identity that names no registered provider is a denominator failure, not
/// a fallback to the first or nearest slot.
pub(crate) fn registered_slot_for(contributing: &str) -> Result<ProviderRole, ContextError> {
    for slot in registered_providers()? {
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
