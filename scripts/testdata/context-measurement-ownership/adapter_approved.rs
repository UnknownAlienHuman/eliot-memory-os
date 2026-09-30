/// Bounded exact approved tokenizer-adapter fixture for #787 case 23.
pub struct ApprovedAdapterBinding {
    pub provider_id: String,
    pub model_id: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub tokenizer_hash: String,
    pub serializer_id: String,
    pub serializer_options_digest: String,
    pub envelope_digest: String,
}

pub fn count_with_approved_adapter(
    binding: &ApprovedAdapterBinding,
    final_serialized_bytes: &[u8],
) -> Result<u64, ContextError> {
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
    Ok(observed_tokens)
}
