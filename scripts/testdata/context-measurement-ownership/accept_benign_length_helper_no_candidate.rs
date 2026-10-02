// Frozen fixture for #787 case 7: a NEGATIVE CONTROL for candidate enumeration.
//
// A plain `len()` helper with no byte ratio, no character ratio and no
// estimator-shaped name. It must enumerate NO candidate and produce NO finding.
// Without this control, a trigger arm that simply matched every `fn` declaration
// -- or every `len()` call -- would satisfy the detection cases while measuring
// nothing.
fn ordinary_length(text: &str) -> usize {
    text.len()
}
