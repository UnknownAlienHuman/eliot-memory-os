// Frozen fixture for #787 case 22: the canonical #704 STU formula in ITS owner.
//
// The audit requires "canonical #704 STU formula accepted only in its owner".
// This is the one place `stu_for_bytes` is legitimate: the normative I2.16
// Source-Token-Unit rule, ceil(bytes/3), defined once inside #704's own crate
// scope. When materialised under the canonical owner path
// `crates/smart/eliot-context-measurement/src/`, this is the single canonical
// definition the oracle must accept and report as the one measurement owner;
// materialised anywhere else it is the duplicate-owner rejection of case 16.
pub fn stu_for_bytes(byte_count: u64) -> u64 {
    if byte_count == 0 {
        return 0;
    }
    byte_count.div_ceil(3)
}

// The declared denominator anchor for this fixture path: the case adds it as an
// extra #866 case so the file becomes a declared scan root of the generated
// artifact, and the oracle's owner scan then sees the definition above.
pub fn declared_len_of(text: &str) -> u64 {
    text.len() as u64
}
