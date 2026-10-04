// EXPECTED: raise=malformed-rust-source detail=unclosed byte-string literal
// This file holds exactly ONE double-quote byte, the one that opens the byte
// string on the last line, for the same whole-remainder reason as the raw and
// ordinary string controls.
// Owner script: 570-589 scan the literal, 586-587 break on the newline, 590-591
// raise when the literal never closed.
// Oracle: 782-789 call the helper on the byte after the quote, 671-674 return
// None at the newline, 786-787 raise the same detail.
const BODY: &[u8] = b"this byte string is opened and never closed
