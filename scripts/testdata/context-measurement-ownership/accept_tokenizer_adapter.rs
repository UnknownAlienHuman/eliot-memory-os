// Bounded accept fixture: an exact authorized tokenizer adapter.
//
// The adapter implements the #704 measurement port, binds provider / model /
// tokenizer id, version and hash to the final serialized bytes, performs no
// admission or fit policy of its own, and stays content-digest bound. This
// is the only shape a consumer may use instead of the canonical owner.

use eliot_context_contracts::TokenizerObservation;

pub struct TokenizerAdapterBinding {
    pub provider_id: String,
    pub model_id: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub tokenizer_hash: String,
    pub serializer_id: String,
    pub serializer_options_digest: String,
    pub envelope_digest: String,
}

pub fn count_with_route_tokenizer(
    binding: &TokenizerAdapterBinding,
    final_serialized_bytes: &[u8],
) -> Result<TokenizerObservation, ContextError> {
    if binding.envelope_digest != sha256_hex(final_serialized_bytes) {
        return Err(ContextError::EnvelopeDigestMismatch);
    }
    let observed_tokens = run_provider_tokenizer(
        &binding.provider_id,
        &binding.model_id,
        &binding.tokenizer_id,
        &binding.tokenizer_version,
        &binding.tokenizer_hash,
        final_serialized_bytes,
    )?;
    Ok(TokenizerObservation {
        provider_id: binding.provider_id.clone(),
        model_id: binding.model_id.clone(),
        tokenizer_id: binding.tokenizer_id.clone(),
        tokenizer_version: binding.tokenizer_version.clone(),
        tokenizer_hash: binding.tokenizer_hash.clone(),
        envelope_digest: binding.envelope_digest.clone(),
        observed_tokens: Some(observed_tokens),
    })
}
