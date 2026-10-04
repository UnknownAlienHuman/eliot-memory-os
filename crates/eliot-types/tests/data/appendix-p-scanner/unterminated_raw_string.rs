// EXPECTED: raise=malformed-rust-source detail=unclosed raw string literal
// This file holds exactly ONE double-quote byte, the one that opens the raw
// literal on the last line. That matters because for the zero-hash form the
// terminator IS a double quote, and both scanners search the whole remainder
// of the file for it rather than stopping at the end of the line.
// Owner script: 634-635 match the opener, 640-642 search and raise when the
// terminator is absent.
// Oracle: 830-836 match the opener, 697-702 search, 843-844 raise the same
// detail. A double quote added anywhere below the opener would stop the raise.
const BODY: &str = r"this raw string is opened and never closed
