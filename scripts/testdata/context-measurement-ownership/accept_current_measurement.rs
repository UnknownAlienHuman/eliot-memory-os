// Bounded accept fixture: a current final-serialized measurement with exact
// tokenizer identity, and an explicitly unvalidated STU estimate with unknown
// actual count carried only at the estimate proof ceiling.
//
// I2.16: the exact `rendered_utf8_bytes` proves route fit; `stu_estimate`
// remains a conservative estimate and never proves fit; `tokenizer` is an
// observation from an actually-run route tokenizer and is never fabricated
// locally. The STU here sits strictly at the estimate ceiling: it carries no
// `proves_fit`, no `actual_tokens`, and no Safety-Floor authority.

use eliot_context_measurement::stu_for_bytes;

pub struct CurrentSerializedMeasurement {
    pub envelope_digest: String,
    pub serializer_id: String,
    pub serializer_options_digest: String,
    pub route_id: String,
    pub model_id: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub tokenizer_hash: String,
    pub final_bytes: u64,
    pub observed_tokens: u64,
    pub stu_estimate: u64,
}

pub fn measure_final_serialized_context(
    route: &Route,
    serializer: &Serializer,
    final_serialized_bytes: &[u8],
    observed_tokens: u64,
) -> CurrentSerializedMeasurement {
    let final_bytes = final_serialized_bytes.len() as u64;
    let envelope_digest = sha256_hex(final_serialized_bytes);
    let stu_estimate = stu_for_bytes(final_bytes).unwrap_or(0);
    CurrentSerializedMeasurement {
        envelope_digest,
        serializer_id: serializer.serializer_id.clone(),
        serializer_options_digest: serializer.serializer_options_digest.clone(),
        route_id: route.route_id.clone(),
        model_id: route.model_id.clone(),
        tokenizer_id: route.tokenizer_id.clone(),
        tokenizer_version: route.tokenizer_version.clone(),
        tokenizer_hash: route.tokenizer_hash.clone(),
        final_bytes,
        observed_tokens,
        stu_estimate,
    }
}
