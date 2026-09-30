// Bounded reject fixture: a multiline character-count token estimate.
// A UTF-8 character count divided by four and carried as tokens. This is a
// character count, not a tokenizer count, and it must be rejected.

pub fn estimate_description_tokens(description: &str) -> usize {
    let character_count = description.chars().count();
    let tokens = character_count.div_ceil(4);
    tokens
}
