// Frozen fixture for #787 cases 6 and 32: a source file whose CONTENT changes
// while its measured signal stays in place.
//
// The case generates the inventory against these exact bytes, then appends a
// comment and re-evaluates. The `declared_len` signal still sits on the same
// line, so the row's span is unchanged, but the FILE digest has moved. That is
// the precise distinction the audit requires: a source change that does not
// relocate a measurement site must still invalidate the previously accepted
// result through the recorded per-row and header source digests.
pub fn declared_len_of(text: &str) -> u64 {
    text.len() as u64
}
