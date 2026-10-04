// EXPECTED: raise=malformed-rust-source detail=unclosed string literal
// This file holds exactly ONE double-quote byte, the one that opens the string
// literal on the last line. The owner stops that scan at the newline; the
// oracle would keep looking for a closing quote across the newline, so the
// single-quote rule above is what makes the two agree on the raise.
// Owner script: 600-617 scan the literal, 615-616 break on the newline, 619-620
// raise when the literal never closed.
// Oracle: 803-810 call the helper, 671-674 return None at the newline, 806-807
// raise the same detail.
const BODY: &str = "this ordinary string is opened and never closed
