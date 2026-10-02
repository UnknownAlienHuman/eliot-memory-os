// Frozen fixture for #787 audit section 4, bullet 4 GAP 2 (declared length arm):
// the payload argument is a REAL, non-empty final serialized byte payload and
// every identity conjunct is genuinely bound, but the record declares
// `declared_len: 0` -- a literal zero length for a non-empty payload.
//
// This MUST be REJECTED, and it isolates the declared-length arm alone: the
// payload conjunct passes, the identity conjuncts pass, and the ONLY failing
// conjunct is the zero declared length. Before the repair, `declared_len` was a
// bare NAME match, so a record claiming a zero-length envelope passed as the
// binding of the final serialized bytes.
use eliot_context_measurement::{
    RouteIdentity, SerializedContextInputs, SerializerIdentity, TokenizerIdentity,
    measure_serialized_context,
};

pub struct ZeroLengthRequest {
    pub payload: Vec<u8>,
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

pub fn measure_zero_declared_length(request: &ZeroLengthRequest) -> Result<u64, String> {
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
    let measured = measure_serialized_context(&request.payload, &inputs)
        .map_err(|error| format!("{error:?}"))?;
    Ok(measured.measurement.rendered_utf8_bytes)
}