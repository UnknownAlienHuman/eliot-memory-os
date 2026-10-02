// Frozen fixture for #787 case 15: a DUPLICATE measurement schema.
//
// The audit rejects "duplicate current SerializedContextMeasurement-equivalent
// schemas" and permits only "nondivergent aliases/reexports ... as inventoried
// projections, not a second mutable schema". This file declares its OWN
// `struct SerializedContextMeasurement` with mutable fields, in a consumer
// crate, so the oracle must find two mutable definitions and reject it as
// DUPLICATE_SCHEMA. A `use`/re-export would be a nondivergent alias and is
// deliberately NOT what this fixture declares.
use std::collections::BTreeMap;

pub struct SerializedContextMeasurement {
    pub measurement_id: String,
    pub declared_len: u64,
    pub content_digest: String,
    pub observed_tokens: u64,
    pub extra: BTreeMap<String, String>,
}

pub fn build_local_measurement(id: &str) -> SerializedContextMeasurement {
    SerializedContextMeasurement {
        measurement_id: id.to_owned(),
        declared_len: 0,
        content_digest: String::new(),
        observed_tokens: 0,
        extra: BTreeMap::new(),
    }
}

// The declared denominator anchor for this fixture path: the case adds it as an
// extra #866 case so the file becomes a declared scan root of the generated
// artifact, and the oracle's own schema scan then sees the duplicate above.
pub fn declared_len_of(text: &str) -> u64 {
    text.len() as u64
}
