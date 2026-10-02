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

/// Compute a whole-multiple covering UTF-8 byte length for `units` STU.
///
/// This is a covering member of the inverse set of the normative
/// `STU(bytes) = ceil(bytes / 3)` owned by this module, and it is NOT the
/// smallest member. The covering set is `b >= 3u - 2`: for `u >= 1`,
/// `ceil(b / 3) >= u` holds exactly when `b >= 3u - 2`, so the smallest
/// covering length is `3u - 2`, and `ceil((3u - 1) / 3) = u` (not `u - 1`) and
/// `ceil((3u - 2) / 3) = u` as well.
///
/// The returned `3u` is the whole-multiple member of that covering set: it
/// never under-covers, so it is an upper bound on the smallest covering length
/// and never evidence of an observed one. It is returned rather than `3u - 2`
/// so the ratio stays exactly three bytes per unit and this function never
/// introduces a second ratio.
///
/// The round-trip `stu_for_bytes(bytes_for_stu(u)?) == u` holds for every `u`
/// this function accepts, and that is all the round-trip proves: it shows `3u`
/// is A covering length whose `STU` estimate still covers `u`, never that it
/// is the smallest one. `STU` is many-to-one, so no inverse of it recovers an
/// observed length. `u = 64` is produced by every `b` in `190..=192`, and
/// `u = 1` is produced by every `b` in `1..=3`; the value this function returns
/// is one of those lengths, not a measurement of which one occurred. For `u = 0`
/// only `b = 0` estimates to `0`, and this function returns `0`, that sole
/// member of the covering set: `u = 0` needs no covering length at all, because
/// `ceil(b / 3) = 0` holds exactly when `b = 0`. The inverse image of `0` is the
/// singleton `{ 0 }`; `1` is produced by every `b` in `1..=3` and by no other
/// length, so the zero boundary is exactly one byte wide.
///
/// This is a covering estimate, not a measurement. It never converts a
/// measured unit count into an observed byte count; it only names the byte
/// length a caller must store when the field it fills is a byte-denominated
/// covering ESTIMATE but its producer carries a unit count, so one integer
/// cannot silently mean two units. A caller holding an actual serialized
/// length must report that length directly and must not round-trip it through
/// this function.
///
/// Unit counts beyond `u64::MAX / 3` have no representable covering length
/// and fail closed with [`ContextError::Overflow`] instead of wrapping.
pub fn bytes_for_stu(units: u64) -> Result<u64, ContextError> {
    units.checked_mul(3).ok_or(ContextError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    // WORK_UNIT_CASE: 880/1
    #[test]
    fn bytes_for_stu_round_trips_every_unit_count() -> Result<(), ContextError> {
        // The round-trip is true, and it is the ONLY property it establishes:
        // the returned length COVERS `units`, never that it is the smallest.
        for units in [0_u64, 1, 2, 3, 4, 63, 64, 65, 1_000, u64::MAX / 3] {
            let covering = bytes_for_stu(units)?;
            assert_eq!(stu_for_bytes(covering)?, units);
            assert!(covering >= units.saturating_mul(3).saturating_sub(2));
        }
        Ok(())
    }

    // WORK_UNIT_CASE: 880/2
    #[test]
    fn bytes_for_stu_is_not_the_smallest_covering_length() -> Result<(), ContextError> {
        // The concrete falsification of the removed minimality claim: for u = 1
        // the smallest covering length is 1 (`stu_for_bytes(1) == 1`), while the
        // function returns 3 because it returns the whole-multiple member.
        assert_eq!(stu_for_bytes(1)?, 1);
        assert_eq!(bytes_for_stu(1)?, 3);
        assert!(bytes_for_stu(1)? > stu_for_bytes(1)?);

        // The repository fixture u = 64: the smallest covering length is
        // 3*64 - 2 = 190 and the function returns 192.
        let smallest = 64_u64 * 3 - 2;
        assert_eq!(stu_for_bytes(smallest)?, 64);
        assert_eq!(stu_for_bytes(smallest - 1)?, 63);
        assert_eq!(bytes_for_stu(64)?, 192);
        assert!(bytes_for_stu(64)? > smallest);

        // u = 0: only the length 0 estimates to 0, and 0 is that singleton
        // covering set's sole member. The zero boundary is exactly one byte wide.
        assert_eq!(stu_for_bytes(0)?, 0);
        assert_eq!(bytes_for_stu(0)?, 0);
        Ok(())
    }

    // This test carries no WORK_UNIT_CASE marker: the four markers already in
    // this file are a scope decision belonging to #704's owner and #866/#787,
    // and this repair neither removes nor renumbers them.
    #[test]
    fn stu_is_zero_only_for_the_zero_length() -> Result<(), ContextError> {
        // `ceil(len / 3) == 0` holds exactly when `len == 0`; the lengths 1 and 2
        // are produced by `u = 1`, so the old `0..=2` zero claim was false and its
        // loop failed at len = 1. Pin both sides of the boundary so neither a
        // widening of the zero set nor a regression to 0 can pass silently.
        assert_eq!(stu_for_bytes(0)?, 0);

        // First non-zero value: len = 1 is the first length with a non-zero
        // estimate, and it estimates to exactly 1.
        assert_eq!(stu_for_bytes(1)?, 1);
        assert_ne!(stu_for_bytes(1)?, 0);

        // The boundary is exactly one byte wide: no length in 1..=2 estimates to 0.
        for len in 1_u64..=2 {
            assert_eq!(stu_for_bytes(len)?, 1);
        }

        // Exhaustively for a small range: the inverse image of 0 is the singleton
        // { 0 }, and 1 is produced by every length in 1..=3 and by no other.
        for len in 0_u64..=64 {
            assert_eq!(
                stu_for_bytes(len)? == 0,
                len == 0,
                "zero-boundary mismatch at len = {len}"
            );
        }
        for len in 1_u64..=3 {
            assert_eq!(stu_for_bytes(len)?, 1);
        }
        assert_eq!(stu_for_bytes(4)?, 2);
        assert_eq!(bytes_for_stu(0)?, 0);
        Ok(())
    }

    // WORK_UNIT_CASE: 880/3
    #[test]
    fn one_unit_count_covers_multiple_lengths_so_none_is_observed() -> Result<(), ContextError> {
        // STU is many-to-one: 190, 191 and 192 all estimate to 64. A single
        // inverse output therefore cannot name which length occurred, so no
        // value derived this way can be an observed byte count.
        for len in 190_u64..=192 {
            assert_eq!(stu_for_bytes(len)?, 64);
        }
        assert_eq!(bytes_for_stu(64)?, 192);
        assert_ne!(bytes_for_stu(64)?, 190);
        assert_ne!(bytes_for_stu(64)?, 191);

        // u = 1 is produced by every length in 1..=3, and no other length.
        for len in 1_u64..=3 {
            assert_eq!(stu_for_bytes(len)?, 1);
        }
        assert_eq!(stu_for_bytes(0)?, 0);
        assert_eq!(stu_for_bytes(4)?, 2);
        Ok(())
    }

    // WORK_UNIT_CASE: 880/4
    #[test]
    fn bytes_for_stu_refuses_the_overflow_boundary() {
        assert_eq!(bytes_for_stu(u64::MAX / 3), Ok((u64::MAX / 3) * 3));
        assert_eq!(bytes_for_stu(u64::MAX / 3 + 1), Err(ContextError::Overflow));
        assert_eq!(bytes_for_stu(u64::MAX), Err(ContextError::Overflow));
    }
}
