// EXPECTED: raise=none detail=none masked=clean
// This is the ONE fixture in the negative set that must NOT raise, and that is
// the whole point of it. An opening quote the char pattern cannot match is a
// lifetime tick or a stray quote, and both scanners KEEP it on purpose so the
// surrounding code stays visible to discovery. Without that rule the single
// hand-written decoder shape in the frozen domain would read as an unclosed
// literal, which is why the rule exists at all.
// Owner script: 622-633, the else branch writes the quote back at 631.
// Oracle: 812-822, the else branch writes the quote back at 819.
// The bytes below are genuinely unterminated: opening quote, one character, no
// closing quote. Masking must succeed and the masked copy must still carry the
// quote, which is the observable difference from the byte-char control above.
pub const UNTERMINATED: char = 'u
