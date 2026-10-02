// Frozen fixture for #787 case 7: the SAME expression split across lines.
//
// The audit's helper fits on one line; any rustfmt run over a longer receiver
// pushes the receiver, the `.len()` and the `div_ceil(4)` onto separate lines.
// A locator that reads a single line would miss the receiver, so this fixture
// pins that the enumeration is line-local but span-anchored on the enclosing
// item: line 1 is the estimator declaration and line 4 is the byte ratio, and
// BOTH must enumerate and BOTH must be reported as unaccounted.
//
// Line numbers are load-bearing: `reject_audit_helper_no_stored_row.rs` is the
// one-line form of the identical expression, so the two fixtures together make
// line-splitting observable rather than assumed.
fn estimate_tokens_split(text: &str) -> usize {
    text.as_bytes()
        .len()
        .div_ceil(4)
}
