// Frozen fixture for #866: normative STU estimate (normative-stu-estimate).
pub fn stu_for_bytes(len: u64) -> u64 {
    len.checked_add(2).map(|v| v / 3).unwrap_or(0)
}
