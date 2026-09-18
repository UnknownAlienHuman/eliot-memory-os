//! Normative Source Token Unit estimate owned solely by issue #704.
//!
//! `STU(bytes) = ceil(UTF-8 byte length / 3)` over the final serialized
//! envelope bytes (I2.16). This module is the single place in the package
//! that divides a byte count by three; every other module calls
//! [`stu_for_bytes`]. There is no competing byte/3 fallback: cited
//! Appendix-O candidates are evidence only and can never replace this
//! function silently.

use eliot_context_contracts::ContextError;

/// Compute `ceil(len / 3)` with checked arithmetic.
///
/// Every accepted length maps to `(len + 2) / 3`. Lengths within two of
/// [`u64::MAX`] cannot add the rounding term and fail closed with
/// [`ContextError::Overflow`] instead of wrapping.
pub fn stu_for_bytes(len: u64) -> Result<u64, ContextError> {
    len.checked_add(2)
        .map(|plus_two| plus_two / 3)
        .ok_or(ContextError::Overflow)
}
