// Bounded reject fixture: a generic local estimator owner. A module outside
// the #704 owner declares its own generic STU/token estimator, becoming a
// second estimation authority alongside the canonical one. It must be
// rejected as a generic estimator owner.

pub fn estimate_context_cost(payload_utf8: &str) -> u64 {
    let bytes = payload_utf8.len() as u64;
    bytes.div_ceil(3)
}
