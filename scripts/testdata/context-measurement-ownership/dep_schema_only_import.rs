// Frozen fixture for #787 defect 4: a SCHEMA-ONLY import. #584's public
// Context contract crate is a real Cargo dependency and a real import, but it
// owns the measurement SCHEMA, not the measurement algorithm: #704's port is
// never called here, so this must be rejected as MISSING_DEPENDENCY.
use eliot_context_contracts::{ContextError, SerializedContextMeasurement};

pub fn envelope_report(bytes: &[u8]) -> Result<u64, ContextError> {
    let measurement = SerializedContextMeasurement {
        schema_version: 1,
        serialized_bytes: bytes.len() as u64,
    };
    Ok(measurement.serialized_bytes)
}