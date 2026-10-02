// Frozen fixture for #787 audit section 4, bullet 4 GAP 2: the port is called
// with `&[]` -- an EMPTY byte slice, i.e. NO serialized bytes at all -- and the
// record declares `declared_len: 0` to match. Every other conjunct is genuinely
// bound: the envelope digest is a real per-request digest and the serializer,
// route (provider + model) and tokenizer id/version/hash are all named.
//
// This MUST be REJECTED, for exactly two reasons the fixture isolates:
//   1. the payload argument is a literal empty slice, so no final serialized
//      bytes are bound; and
//   2. the declared envelope length is the literal zero, so the record asserts
//      an empty envelope while presenting itself as a bound observation.
//
// Before the repair both probes passed as "final serialized bytes": the payload
// conjunct was not computed at all and a zero `declared_len` was only a NAME
// match on `declared_len`.
use eliot_context_measurement::{
    RouteIdentity, SerializedContextInputs, SerializerIdentity, TokenizerIdentity,
    measure_serialized_context,
};

pub struct EmptyEnvelopeRequest {
    pub content_digest: String,
    pub serializer_id: String,
    pub serializer_version: String,
    pub serializer_options_digest: String,
    pub schema_revision: String,
    pub route_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub tokenizer_hash: String,
    pub tokenizer_config_digest: String,
}

pub fn measure_empty_envelope(request: &EmptyEnvelopeRequest) -> Result<u64, String> {
    let inputs = SerializedContextInputs {
        measurement_id: request.content_digest.clone(),
        declared_len: 0,
        content_digest: request.content_digest.clone(),
        serializer: SerializerIdentity {
            serializer_id: request.serializer_id.clone(),
            serializer_version: request.serializer_version.clone(),
            serializer_options_digest: request.serializer_options_digest.clone(),
            schema_revision: request.schema_revision.parse().map_err(|_| "bad revision")?,
        },
        route: RouteIdentity {
            route_id: request.route_id.clone(),
            provider_id: request.provider_id.clone(),
            model_id: request.model_id.clone(),
        },
        tokenizer: TokenizerIdentity {
            tokenizer_id: request.tokenizer_id.clone(),
            tokenizer_version: request.tokenizer_version.clone(),
            tokenizer_hash: request.tokenizer_hash.clone(),
            tokenizer_config_digest: request.tokenizer_config_digest.clone(),
        },
        max_serialized_bytes: u64::MAX,
    };
    let measured = measure_serialized_context(&[], &inputs)
        .map_err(|error| format!("{error:?}"))?;
    Ok(measured.measurement.rendered_utf8_bytes)
}