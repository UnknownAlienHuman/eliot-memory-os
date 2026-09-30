// Bounded reject fixture: an actual observation that does not carry the exact
// serialized bytes and the route / model / tokenizer identity. An actual
// observation without its serialized-byte and identity binding is unusable
// evidence and must be rejected.

pub struct UnboundObservation {
    pub observed_tokens: u64,
}

pub fn observe_tokens_only(body: &str) -> UnboundObservation {
    // The count is produced, but the exact final serialized bytes, the route
    // id, the model id and the tokenizer identity are all absent, so the
    // observation cannot be bound to anything and proves nothing.
    let observed_tokens = guess_tokens(body);
    UnboundObservation { observed_tokens }
}
