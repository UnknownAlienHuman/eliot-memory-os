// Frozen fixture for #787 case 29: CRLF endings, non-ASCII text, and PRODUCTION
// code that appears AFTER a `#[cfg(test)]` module.
//
// Three classification hazards in one file:
//   1. CRLF line endings -- the producer's masking and line arithmetic must
//      still place every span on the right line;
//   2. non-ASCII (Cyrillic/CJK) content, so a byte-vs-character confusion in
//      the reader cannot silently pass;
//   3. a `#[cfg(test)] mod tests` block followed by MORE PRODUCTION code --
//      a scanner that assumes everything after the first `#[cfg(test)]` is
//      test scope would wrongly reclassify `pub fn` below as test-only, and one
//      that assumes everything before it is production would miss the real
//      test-only span. The helper below is production; the module above it is
//      not.
pub fn production_helper_after_tests(text: &str) -> usize {
    text.as_bytes().len()
}

#[cfg(test)]
mod tests {
    #[test]
    fn counts_bytes() {
        assert_eq!(super::production_helper_after_tests("привет"), 12);
    }
}
