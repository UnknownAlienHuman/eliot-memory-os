// Frozen fixture for #787 case 9: a SEMANTIC bytes/4 estimate.
//
// The audit rejects "semantic Context uses of `/4`/div_ceil(4)/equivalent
// ratios". This helper divides a serialized Context payload's byte length by
// four and returns it as a token count -- a planning ratio with no tokenizer
// behind it. The #866 classifier must place it in
// `token_estimate_without_tokenizer` (BYTE_RATIO) and the oracle must report
// it as an unaccounted candidate naming this path and span.
pub fn estimate_context_tokens(text: &str) -> usize {
    text.as_bytes().len().div_ceil(4)
}
