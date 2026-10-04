// EXPECTED: raise=malformed-rust-source detail=unclosed block comment
// This file holds exactly one double-quote byte above the opener and none
// after it, so the raise below can only be the unterminated block comment.
// Owner script: 564-565 open the block comment, 664-665 raise when the depth
// is still positive at end of source.
// Oracle: 774-781 open the block comment, 853-855 raise the same detail.
// Everything above the comment is well-formed Rust and masks cleanly.
pub fn well_formed_prefix() -> &'static str {
    "masked and closed correctly before the unclosed comment"
}

/* This block comment is opened here and never closed, so both scanners reach
 * end of source with the block depth still positive and must refuse the file
 * instead of blanking the remainder as if it were code.
