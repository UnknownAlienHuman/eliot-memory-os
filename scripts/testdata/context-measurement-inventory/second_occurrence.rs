// Frozen fixture for #866: one estimator needle in two production items.
// The `stu_for_bytes` needle occurs in two enclosing items (proof item 3).
pub fn stu_for_bytes(len: u64) -> u64 {
    len.checked_add(2).map(|v| v / 3).unwrap_or(0)
}
pub fn stu_for_bytes_with_headroom(len: u64, headroom: u64) -> u64 {
    stu_for_bytes(len).saturating_add(headroom)
}
