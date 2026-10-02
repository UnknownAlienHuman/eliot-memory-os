// Frozen fixture for #787 case 18: an ACTUAL observation missing its
// serializer/route/model/tokenizer binding.
//
// The audit rejects "actual observations without exact serialized bytes and
// route/model/tokenizer identity". This consumer records an `observed_tokens`
// count and claims it is the current actual count, but the observation is
// never bound to the final serialized bytes (no `declared_len` /
// `content_digest`) and never to the serializer, route, model or tokenizer
// identity. A real port call therefore cannot carry the proof, and the oracle
// must report MISSING_DEPENDENCY naming the exact unbound conjuncts.
use eliot_context_measurement::measure_serialized_context;

pub struct LooseObservation {
    pub observed_tokens: u64,
    pub current: bool,
}

pub fn observe_tokens(bytes: &[u8]) -> LooseObservation {
    let observed_tokens = measure_serialized_context(bytes).unwrap_or(0);
    LooseObservation {
        observed_tokens,
        current: true,
    }
}
