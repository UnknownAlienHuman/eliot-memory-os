// EXPECTED: raise=malformed-rust-source detail=unclosed byte-char literal
// The literal below is a quote, a BACKSLASH, a real newline, and a quote.
// Owner script: 593-596 match b' then either a backslash pair or one char that
// is neither quote nor backslash. Python's dot does not match a newline and no
// re.DOTALL is passed, so the backslash pair cannot span the newline; and the
// second alternative cannot START on a backslash at all. No match, so 596
// raises. The oracle takes the same view for a different stated reason:
// 637-639 refuses an escaped newline outright, and 794-795 raises.
// Both must refuse this file.
const ESCAPED_NEWLINE: u8 = b'\
';
