//! Closed effecting-path readiness gate (issue #1108, items A4/A5).
//!
//! Production construction and production restore admit effects only from a
//! capability that carries its factory-witnessed durable owner row: the row
//! the closed [`AdmittedProviderFactory`](crate::admitted_provider::AdmittedProviderFactory)
//! proved the presented halves equal to, field for field, before any existing
//! validator observed them. Every later `verify` then reads the loaded legs
//! back from that retained row on each call instead of aliasing the presented
//! half, so one admission binds every proof to the same durable evidence. A
//! rowless capability fails this gate closed with
//! [`CoordinatorError::StaleProviderBinding`]: without retained durable
//! evidence there is nothing to re-prove presented values against, so the
//! effecting path cannot tell a live binding from caller-supplied halves.
//! Caller booleans, provider/model names, proof strings, and liveness
//! observations never reach this gate as evidence.
//!
//! Supplier (M2, issue #22): Kernel over the authenticated front-door session
//! plus ORS operation records bound to the exact attempt; no new signing or
//! token service. This gate mints nothing: it only refuses rowless
//! capabilities before a verifier is built. The row itself is witnessed by
//! the existing factory owner and the per-proof owner checks stay with the
//! existing pure verifier.

use crate::model::CoordinatorError;
use crate::provider_admission::AdmittedProviderCapability;

/// Requires the factory-witnessed durable owner row on the effecting path.
///
/// Returns [`CoordinatorError::StaleProviderBinding`] when the capability
/// carries no retained row. Called by the closed production constructors in
/// [`crate::core`] before any verifier is built, so a rowless capability can
/// never reach an effecting `verify`, plan-only construction is untouched,
/// and restore with missing provider evidence stays blocked instead of
/// silently resuming effects.
pub(crate) fn require_witnessed_binding(
    capability: &AdmittedProviderCapability,
) -> Result<(), CoordinatorError> {
    if capability.witnessed_row().is_some() {
        Ok(())
    } else {
        Err(CoordinatorError::StaleProviderBinding)
    }
}
