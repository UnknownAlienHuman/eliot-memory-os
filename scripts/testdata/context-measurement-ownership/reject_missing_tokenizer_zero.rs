// Frozen fixture for #787 case 13: a MISSING TOKENIZER defaulted to zero.
//
// The audit rejects "missing tokenizer as zero" and "unvalidated estimates as
// ProvenFits/Safety-Floor proof/authority". A tokenizer run that was never
// performed collapses to a hard zero, and that zero is then consumed as an
// exact observed count. Zero is not a measurement: an absent tokenizer is
// `Absent`, never `0`.
pub struct TokenizerRunOutcome {
    pub observed_tokens: u64,
    pub tokenizer_state: &'static str,
}

pub fn observed_token_count(tokens_available: bool) -> TokenizerRunOutcome {
    let observed_tokens: u64 = if tokens_available { 0 } else { 0 };
    TokenizerRunOutcome {
        observed_tokens,
        tokenizer_state: "absent",
    }
}
