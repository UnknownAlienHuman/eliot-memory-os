// Frozen fixture for #787 defect 4: a STRING LITERAL naming the canonical
// symbol and the crate. The masked production span blanks every literal body,
// so nothing here is code and it must be rejected as MISSING_DEPENDENCY.
pub const NOTE: &str = "eliot_context_measurement::measure_serialized_context";

pub fn envelope_report(bytes: &[u8]) -> u64 {
    bytes.len() as u64
}