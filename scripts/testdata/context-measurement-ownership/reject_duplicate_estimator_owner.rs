// Frozen fixture for #787 case 16: a DUPLICATE generic estimator owner.
//
// The audit rejects "generic STU/token estimator owners" and requires exactly
// one canonical measurement implementation owner. This file defines its own
// `stu_for_bytes` -- the exact canonical STU formula name -- outside
// #704's `crates/smart/eliot-context-measurement/` scope, so the oracle must
// report GENERIC_ESTIMATOR_OWNER (a second definition of the canonical entry
// point) rather than treating it as an ordinary local helper.
pub fn stu_for_bytes(byte_count: u64) -> u64 {
    byte_count.div_ceil(3)
}

pub fn measure_serialized_context(bytes: &[u8]) -> u64 {
    stu_for_bytes(bytes.len() as u64)
}

// The declared denominator anchor for this fixture path: the case adds it as an
// extra #866 case so the file becomes a declared scan root of the generated
// artifact, and the oracle's owner scan then sees the duplicate definitions
// above.
pub fn declared_len_of(text: &str) -> u64 {
    text.len() as u64
}
