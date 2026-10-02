// Frozen fixture for #787 case 7: the audit's own helper, byte for byte.
//
// Audit 5931913038 defect 3 states the false-safe counterexample as:
//
//     fn local_estimate_tokens(text: &str) -> usize {
//         text.as_bytes().len().div_ceil(4)
//     }
//
// Appended to an already-declared scan root with NO denominator row, a normal
// #866 sync refreshed the file digest but still emitted only its declared
// signals, so the helper received no row and #787 reported nothing at all.
//
// This file is that helper at its exact declared span: line 1 is the
// declaration, line 2 is the `div_ceil(4)` byte ratio. Case 7 asserts the
// producer enumerates BOTH sites -- the declaration by ESTIMATOR_HELPER_RE and
// the ratio by BYTE_RATIO -- and that the oracle reports the ratio site as
// UNACCOUNTED_CANDIDATE naming this path, this span and BYTE_RATIO.
fn local_estimate_tokens(text: &str) -> usize {
    text.as_bytes().len().div_ceil(4)
}
