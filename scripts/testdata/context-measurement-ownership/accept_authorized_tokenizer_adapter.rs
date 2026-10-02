// Frozen fixture for #787 cases 23 and 26: an EXACT AUTHORIZED tokenizer
// adapter and a current final-serialized measurement with exact tokenizer
// identity.
//
// This is the positive counterpart of every dependency negative. It is a real
// migrated consumer seam: it declares #704's Cargo dependency, calls the
// canonical port `measure_serialized_context` in PRODUCTION, passes the final
// serialized bytes as the payload, and binds BOTH the envelope binding
// (`declared_len` + `content_digest`) and the full identity binding
// (`serializer` + `route` + `tokenizer`, with provider/model/tokenizer
// id+version+hash) into the `SerializedContextInputs` record the port takes.
// Nothing here is a comment, a string, a test-only call, a similarly named
// local function, or dead code.
use eliot_context_measurement::{
    RouteIdentity, SerializedContextInputs, SerializerIdentity, TokenizerIdentity,
    measure_serialized_context,
};

pub struct EnvelopeRequest {
    pub measurement_id: String,
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

pub fn measure_envelope(request: &EnvelopeRequest) -> Result<u64, String> {
    let inputs = SerializedContextInputs {
        measurement_id: request.measurement_id.clone(),
        declared_len: request.payload.len() as u64,
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
