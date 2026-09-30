//! Normative Source Token Unit estimate owned solely by issue #704.
//!
//! `STU(bytes) = ceil(UTF-8 byte length / 3)` over the final serialized
//! envelope bytes (I2.16). This module is the single place in the package
//! that divides a byte count by three; every other module calls
//! [`stu_for_bytes`]. There is no competing byte/3 fallback: cited
//! Appendix-O candidates are evidence only and can never replace this
//! function silently. The covering direction is owned here too: [`bytes_for_stu`]
//! is the only place that re-derives the same three-bytes-per-unit ratio, so
//! no consumer re-implements it as a local factor.

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

/// Compute the smallest UTF-8 byte length whose [`stu_for_bytes`] estimate is
/// at least `units`.
///
/// This is the covering inverse of the normative `STU(bytes) = ceil(bytes / 3)`
/// owned by this module: for `u`, the smallest `b` with `ceil(b / 3) >= u` is
/// exactly `3 * u`, because `ceil(3u / 3) = u` and `ceil((3u - 1) / 3) = u - 1`.
/// It therefore round-trips: `stu_for_bytes(bytes_for_stu(u)?) == u` for every
/// `u` this function accepts.
///
/// This is a length, not a measurement. It never converts a measured unit
/// count into an observed byte count; it only names the byte length a caller
/// must store when the field it fills is byte-denominated but its producer
/// carries a unit count, so one integer cannot silently mean two units. A
/// caller holding an actual serialized length must report that length
/// directly and must not round-trip it through this function.
///
/// Unit counts beyond `u64::MAX / 3` have no representable covering length
/// and fail closed with [`ContextError::Overflow`] instead of wrapping.
pub fn bytes_for_stu(units: u64) -> Result<u64, ContextError> {
    units.checked_mul(3).ok_or(ContextError::Overflow)
}
