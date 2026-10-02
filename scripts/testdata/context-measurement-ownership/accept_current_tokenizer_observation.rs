// Frozen fixture for #787 case 26: a CURRENT final-serialized measurement
// with EXACT tokenizer identity.
//
// The audit requires a current measurement to bind the final serialized bytes
// AND the provider/model/tokenizer id+version+hash. This fixture records the
// observation as it must be recorded: the serialized byte length and content
// digest of the exact payload that was sent, the route that carried it, and
// the tokenizer identity including its version and content hash. Nothing here
// is estimated, and nothing is claimed beyond what was actually run.
pub struct CurrentObservation {
    pub declared_len: u64,
    pub content_digest: String,
    pub provider_id: String,
    pub model_id: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub tokenizer_hash: String,
    pub observed_tokens: u64,
    pub tokenizer_state: &'static str,
}

pub fn current_observation(
    bytes: &[u8],
    digest: &str,
    provider: &str,
    model: &str,
    tokenizer: &str,
    version: &str,
    hash: &str,
    observed: u64,
) -> CurrentObservation {
    CurrentObservation {
        declared_len: bytes.len() as u64,
        content_digest: digest.to_owned(),
        provider_id: provider.to_owned(),
        model_id: model.to_owned(),
        tokenizer_id: tokenizer.to_owned(),
        tokenizer_version: version.to_owned(),
        tokenizer_hash: hash.to_owned(),
        observed_tokens: observed,
        tokenizer_state: "measured",
    }
}
