// Bounded reject fixture: a semantic Context use of the /4 ratio.
// A serialized byte length divided by four and carried as tokens. No route
// tokenizer ever ran. This must be rejected.

pub fn estimate_context_cost(serialized_bytes: u64) -> u64 {
    serialized_bytes.div_ceil(4)
}
