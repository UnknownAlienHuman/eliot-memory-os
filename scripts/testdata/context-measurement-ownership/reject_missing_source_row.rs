// Frozen fixture for #787 case 5: a MISSING source row.
//
// The stored inventory declares a measurement signal in this file. The case
// removes that signal from the live source, so the producer can no longer
// locate the declared identity and the stored row no longer corresponds to
// any live source span. The oracle must report SOURCE_ROW_MISSING naming the
// case and the file.
pub fn unrelated_helper(text: &str) -> usize {
    text.len()
}
