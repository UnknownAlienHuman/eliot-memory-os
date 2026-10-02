// Frozen fixture for #787 defect 4: a canonical import and a genuine call to
// #704's port that exist ONLY inside #[cfg(test)] / a #[test] fn. The Cargo
// dependency and the exact call are both real, so only the measured test scope
// keeps it from satisfying the production dependency; it must be rejected as
// MISSING_DEPENDENCY with the test-only scope named as the reason.
use eliot_context_measurement::{SerializedContextInputs, measure_serialized_context};

fn build_inputs() -> SerializedContextInputs {
    SerializedContextInputs {
        measurement_id: "m-1".to_owned(),
        declared_len: 2,
        content_digest: "sha256:00".to_owned(),
        max_serialized_bytes: 64,
    }
}

pub fn envelope_report(bytes: &[u8]) -> u64 {
    bytes.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_serialized_payload() {
        let inputs = build_inputs();
        let measured = measure_serialized_context(b"{}", &inputs).expect("measurement succeeds");
        assert_eq!(measured.measurement.rendered_utf8_bytes, 2);
    }
}