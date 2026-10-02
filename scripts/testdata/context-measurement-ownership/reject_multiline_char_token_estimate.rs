// Frozen fixture for #787 case 10: a MULTILINE character-count token estimate.
//
// The audit rejects "character/UTF-16/grapheme counts labeled tokens/STU". Here
// the character count is divided by four and carried as tokens, with the
// expression split across lines so that neither the receiver, the length nor
// the ratio sits on a single line. The #866 CHAR_RATIO arm must still observe
// it and classify it as `character_count_mislabeled_as_tokens`.
pub fn estimate_character_tokens(text: &str) -> usize {
    text.chars()
        .count()
        .div_ceil(4)
}
