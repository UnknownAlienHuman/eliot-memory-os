// Canonical #704 STU owner fixture (bounded exact copy for #787 tests).
//
// The normative Source Token Unit estimate. This is the ONLY place in the
// declared scan roots that divides a byte count by three; every other module
// calls `stu_for_bytes`. I2.16: STU = ceil(UTF-8 bytes / 3).

/// Compute `ceil(len / 3)` with checked arithmetic.
pub fn stu_for_bytes(len: u64) -> Result<u64, ContextError> {
    len.checked_add(2)
        .map(|plus_two| plus_two / 3)
        .ok_or(ContextError::Overflow)
}
