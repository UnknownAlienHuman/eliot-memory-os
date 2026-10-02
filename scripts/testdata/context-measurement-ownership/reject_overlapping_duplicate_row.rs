// Frozen fixture for #787 case 8: an OVERLAPPING / duplicate row.
//
// Two inventory rows claim the SAME source span -- the identical
// `(path, span_start)` identity -- under different case references. The audit
// rejects "overlapping/duplicate row": one exact source span has exactly one
// owner and exactly one row. This file supplies the single line both rows
// point at, so a fixture that anchors both rows at line 2 is a real overlap in
// live source and not a synthetic contradiction.
pub fn declared_len_of(text: &str) -> u64 {
    text.len() as u64
}
