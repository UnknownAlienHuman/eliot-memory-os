// Frozen fixture for #787 case 11: a helper/constant ALIAS hiding the ratio.
//
// The audit rejects "local generic estimate_tokens/token_units/context_cost
// helpers" and "helper/constant alias hiding ratio". The ratio is not written
// at the call site: it is hidden behind a named constant and a named local
// helper, so only the producer's ESTIMATOR_HELPER_RE declaration arm and its
// BYTE_RATIO body arm can see it.
pub const APPROX_BYTES_PER_TOKEN: usize = 4;

pub fn local_estimate_tokens(text: &str) -> usize {
    text.as_bytes().len().div_ceil(APPROX_BYTES_PER_TOKEN)
}

pub fn context_cost_hint(text: &str) -> usize {
    local_estimate_tokens(text)
}
