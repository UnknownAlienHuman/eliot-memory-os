// Frozen fixture for #787 audit section 4, bullet 4 GAP 1: the port is called
// BARE -- no payload argument at all -- while the enclosing item declares every
// other conjunct (the real final serialized byte payload is available, the
// envelope length/digest and the provider/model/tokenizer ID/version/hash are
// all bound). The call therefore passes NO serialized bytes to the port.
//
// This MUST be REJECTED. Acceptance is a conjunction of the measured binding
// facts; `payload_argument` is one of them and it is None here, so the site is
// not an accepted site however completely the record beside it is bound.
//
// Before the repair, acceptance tested only `final_bytes_bound and
// identity_bound`, so this site was ACCEPTED with `payload_argument: null` --
// precisely the audit's proof that the payload conjunct was computed, reported
// as a gap, and then never gated on.
use eliot_context_measurement::{
    RouteIdentity, SerializedContextInputs, SerializerIdentity, TokenizerIdentity,
    measure_serialized_context,
};

pub struct BareCallRequest {
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

pub fn measure_without_payload(request: &BareCallRequest) -> Result<u64, String> {
    let inputs = SerializedContextInputs {
        measurement_id: request.content_digest.clone(),
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
    let measured = measure_serialized_context()
        .map_err(|error| format!("{error:?}"))?;
    Ok(measured.measurement.rendered_utf8_bytes)
}