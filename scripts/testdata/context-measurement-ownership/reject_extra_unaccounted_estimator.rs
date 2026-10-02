// Frozen fixture for #787 case 7: an extra estimator with NO denominator row.
//
// This is the audit's own counterexample shape (defect 3), reproduced so case
// 7 can assert the typed finding end to end: an estimator is added to an
// already-declared scan root, the artifact is freshly regenerated (so the file
// digest is refreshed and no generic pre-sync mismatch remains), and the
// oracle must STILL report an UNACCOUNTED_CANDIDATE naming this path, this
// span and the #866 rule that fired.
pub fn local_estimate_tokens(text: &str) -> usize {
    text.as_bytes().len().div_ceil(4)
}
