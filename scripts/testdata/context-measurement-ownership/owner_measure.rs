//! Bounded canonical measurement owner fixture for #787 tests.
//!
//! Exact UTF-8 measurement of one serialized context payload. `stu_estimate`
//! is a conservative planning estimate and never proves fit; `tokenizer` is an
//! observation from an actually-run route tokenizer and is never fabricated.

pub struct SerializedContextMeasurement {
    pub envelope_digest: String,
    pub serializer_id: String,
    pub route_id: String,
    pub model_id: String,
    pub rendered_utf8_bytes: u64,
    pub observed_tokens: Option<u64>,
}

pub fn measure_serialized_context(
    params: &MeasurementParams,
) -> Result<SerializedContextMeasurement, ContextError> {
    let rendered_utf8_bytes = params.payload_utf8.len() as u64;
    let envelope_digest = sha256_hex(&params.payload_utf8);
    let stu_estimate = stu_for_bytes(rendered_utf8_bytes).ok();
    let tokenizer = params.tokenizer.clone();
    Ok(SerializedContextMeasurement {
        envelope_digest,
        serializer_id: params.serializer_id.clone(),
        route_id: params.route_id.clone(),
        model_id: params.model_id.clone(),
        rendered_utf8_bytes,
        observed_tokens: tokenizer.map(|observation| observation.observed_tokens),
    })
    .map(|measurement| {
        let _ = stu_estimate;
        measurement
    })
}
