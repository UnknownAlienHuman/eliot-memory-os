// Bounded reject fixture: a byte/KiB value labelled tokens, plus minimum-one
// masking. A KiB-scaled byte value is carried in a field named `tokens`, and
// the result is masked to a minimum of one so an empty payload never reports
// zero. Both are named prohibited constructs.

pub fn token_units(serialized_bytes: u64) -> u64 {
    let kib = serialized_bytes.div_ceil(1024);
    let tokens = kib.max(1);
    tokens
}
