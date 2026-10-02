// Frozen fixture for #787 defect 4: a SIMILARLY NAMED LOCAL function with no
// real binding. Its name shares the canonical port's stem but it is defined
// here, it is not imported from #704, and its Cargo dependency is absent, so it
// must be rejected as MISSING_DEPENDENCY.
fn measure_serialized_context_local(payload: &[u8]) -> u64 {
    payload.len() as u64
}

pub fn envelope_report(bytes: &[u8]) -> u64 {
    measure_serialized_context_local(bytes)
}