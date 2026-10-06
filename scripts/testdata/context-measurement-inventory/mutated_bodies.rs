// Frozen fixture for #866: five measurement bodies under one helper shape.
// Mutation tests keep the signature fixed and swap bodies (proof item 4).
pub fn measure_exact_bytes(input: &[u8]) -> u64 {
    input.len() as u64
}
pub fn measure_ratio4_bytes(input: &[u8]) -> u64 {
    (input.len() / 4) as u64
}
pub fn measure_chars_claimed_tokens(input: &[u8]) -> u64 {
    (String::from_utf8_lossy(input).chars().count() / 4) as u64
}
pub fn measure_minimum_one(input: &[u8]) -> u64 {
    (input.len() as u64).max(1)
}
pub fn measure_rounded_up_sum(input: &[u8]) -> u64 {
    (input.len().div_ceil(4) * 4) as u64
}
