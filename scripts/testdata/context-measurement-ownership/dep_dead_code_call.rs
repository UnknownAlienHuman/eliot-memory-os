// Frozen fixture for #787 defect 4: DEAD CODE. It carries a genuine Cargo
// dependency on #704 and imports the canonical port, but the only call to
// measure_serialized_context sits inside a private function that production
// code never reaches, so no production call binds the dependency and it must be
// rejected as MISSING_DEPENDENCY.
use eliot_context_measurement::{SerializedContextInputs, measure_serialized_context};

#[allow(dead_code)]
fn never_called_measurement_probe(bytes: &[u8]) -> u64 {
    let inputs = SerializedContextInputs {
        measurement_id: "m-dead".to_owned(),
        declared_len: bytes.len() as u64,
        content_digest: "sha256:00".to_owned(),
        max_serialized_bytes: 64,
    };
    measure_serialized_context(bytes, &inputs)
        .map(|measured| measured.measurement.rendered_utf8_bytes)
        .unwrap_or_default()
}

pub fn envelope_report(bytes: &[u8]) -> u64 {
    bytes.len() as u64
}