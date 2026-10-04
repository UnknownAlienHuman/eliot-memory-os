// EXPECTED: default=0 form=none helper=0 paired=0 bare-option=0
// unsupported-macro=0 unresolved=0 manual-visitor=0 raise=none keys=(none) detail=none
// Every construct below is a token one of the scanners had to be hardened
// against. Provoking a site or a raise anywhere in this file is a defect in the
// oracle, not an expected surprise, so the whole expectation is zeros.
// Decoy by decoy, and the line that neutralises it:
//   clippy path segment   allow(clippy::struct_excessive_bools) below. A struct
//     keyword preceded by a colon is a path segment, not a declaration, and
//     the name after it does not end on a declaration boundary either.
//   keyword-prefixed name structured_bytes below. The keyword is followed by
//     ured_bytes, and the byte after that is a colon, not { ( ; < or space.
//   .enumerate() below. A bare dot in front of enum is a method call; the
//     enclosing-type helper rules the dot out, so no type is named erate.
//   lifetime tick   &'static str below. The quote opens no char literal, so it
//     is kept verbatim rather than treated as a raise or blanked as a literal.
//   raw string with braces  RAW_SHAPED below. Masking blanks the body, so the
//     braces cannot unbalance a delimiter count and the fake serde attribute
//     inside it cannot become a span.
//   doc comment naming the trait  the doc line below. Comments are blanked
//     before any attribute or type scan runs.
//   decoder-shaped impl in a block comment  the block comment at the end. The
//     impl token is written on a prefixed line so the line-start anchor on a
//     hand-written decoder cannot count it either.
#[allow(clippy::struct_excessive_bools)]
pub struct DecoyFixture {
    pub structured_bytes: Vec<u8>,
    pub label: &'static str,
}

const RAW_SHAPED: &str = r"braces { } and a fake #[serde(default)] inside a raw string";

/// A doc comment naming Deserialize must never read as a decoder declaration.
pub fn enumerate_rows() -> usize {
    for (index, _row) in (0..3).enumerate() {
        let _ = index;
    }
    0
}

/*
 * impl<'de> Deserialize<'de> for DecoyFixture lives inside this block comment
 * and is written on a prefixed line so the line-start anchor cannot count it.
 */
