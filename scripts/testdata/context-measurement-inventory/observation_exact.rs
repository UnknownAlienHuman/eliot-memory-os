// Frozen fixture for #866: exact tokenizer observation (exact-observation).
pub struct Observation {
    pub source: &'static str,
}
pub const SOURCE: &str = "ProviderTokenizerRun";
pub fn observed_tokens() -> u64 {
    1200
}
