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

/// Compute a covering UTF-8 byte length for `units`: one whose
/// [`stu_for_bytes`] estimate is at least `units`, and which need not be the
/// smallest such length.
///
/// This is a COVERING length for the normative `STU(bytes) = ceil(bytes / 3)`
/// owned by this module, not the smallest one. `ceil(b / 3) >= u` holds exactly
/// when `b >= 3u - 2`, so the smallest covering length is `3u - 2` for
/// `u >= 1` (`1` for `u = 1`). `3 * u` is the whole-multiple member of that
/// covering set - it never under-covers - and this function returns it so the
/// ratio stays exactly three bytes per unit. It therefore round-trips:
/// `stu_for_bytes(bytes_for_stu(u)?) == u` for every `u` this function
/// accepts.
///
/// `STU` is many-to-one, so the returned length is never an exact inverse and
/// no value of it recovers an observed length: `u = 64` is produced by every
/// `b` in `190..=192`, and all of them round-trip to `192` here.
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
