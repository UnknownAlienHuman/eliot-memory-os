// Frozen fixture for #787 defect 4: a COMMENT naming the canonical symbol.
// The masked production span blanks every comment body, so this file carries no
// import, no call and no binding: it must be rejected as MISSING_DEPENDENCY.
pub fn envelope_report(bytes: &[u8]) -> u64 {
    // TODO: call measure_serialized_context for this payload.
    bytes.len() as u64
}