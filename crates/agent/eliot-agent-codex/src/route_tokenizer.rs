//! Codex-route render-time token measurement (issue #1941 C6).
//!
//! Counts exact bytes with the route's actual tokenizer through the
//! owner-published `tiktoken` mappings (`tiktoken-rs` 0.12.0, whose registry
//! is kept in sync with `OpenAI` `tiktoken` `model.py`): `get_tokenizer` maps
//! the exact provider model string verbatim — never normalized, prefixed,
//! or guessed — to its tokenizer (`codex-mini` and the `gpt-5.*-codex`
//! family resolve to `o200k_base`), or reports unmapped. Anything the
//! registry does not name withholds instead of estimating.
//!
//! Counts use `count_ordinary`: result bytes are data, so special-token
//! sequences inside them must never parse as control tokens. Non-UTF-8
//! bytes have no defined count under these text tokenizers and withhold
//! rather than lossy-convert. Rank data is compiled in (`include_str!`
//! assets: no runtime network), and the cached BPE singletons are shared.
//!
//! No tiktoken type escapes this crate, and this crate takes no bridge
//! dependency: public outputs are counts, canonical encoding names, and
//! digests only. The bridge wire payload is assembled by the caller (which
//! holds the live route observation) from [`CodexMeasuredTokens`] fields;
//! the bridge verifies admission linkage and byte binding at intake, never
//! here. Layering is one-way by construction: provider-side measurement
//! never depends on surface contracts.

use sha2::{Digest, Sha256};
use tiktoken_rs::tokenizer::{Tokenizer, get_tokenizer};

use crate::CodexAdapterError;

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Canonical tiktoken encoding that ran a measurement, transcribed verbatim
/// from the registry's documented variant names. The exhaustive match fails
/// closed at compile time if upstream adds a variant, forcing review rather
/// than silent misattribution.
fn encoding_name(tokenizer: Tokenizer) -> &'static str {
    match tokenizer {
        Tokenizer::O200kBase => "o200k_base",
        Tokenizer::O200kHarmony => "o200k_harmony",
        Tokenizer::Cl100kBase => "cl100k_base",
        Tokenizer::P50kBase => "p50k_base",
        Tokenizer::P50kEdit => "p50k_edit",
        Tokenizer::R50kBase => "r50k_base",
        Tokenizer::Gpt2 => "gpt2",
    }
}

/// Tokens counted by the route's actual tokenizer for exact bytes, with the
/// canonical encoding that ran and the digest of the counted bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexMeasuredTokens {
    tokens: u64,
    encoding: &'static str,
    result_digest: String,
}

impl CodexMeasuredTokens {
    /// Token count the route's actual tokenizer reported.
    #[must_use]
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }

    /// Canonical owner-registry encoding name that ran the count.
    #[must_use]
    pub const fn encoding(&self) -> &'static str {
        self.encoding
    }

    /// Lowercase SHA-256 hex of the exact bytes that were counted.
    #[must_use]
    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }
}

/// Counts exact result bytes with the tokenizer the owner registry assigns
/// to `model_id` verbatim. Unmapped model IDs and non-UTF-8 bytes withhold;
/// nothing is normalized, defaulted, or estimated.
///
/// # Errors
///
/// Returns [`CodexAdapterError::UnknownTokenizerModel`] when the registry
/// names no tokenizer for the exact model string,
/// [`CodexAdapterError::UncountableBytes`] when the bytes are not text, or
/// [`CodexAdapterError::TokenizerUnavailable`] when counting cannot
/// complete.
pub fn measure_result_tokens(
    model_id: &str,
    result_bytes: &[u8],
) -> Result<CodexMeasuredTokens, CodexAdapterError> {
    let text =
        std::str::from_utf8(result_bytes).map_err(|_| CodexAdapterError::UncountableBytes)?;
    let tokenizer =
        get_tokenizer(model_id).ok_or_else(|| CodexAdapterError::UnknownTokenizerModel {
            model_id: model_id.to_owned(),
        })?;
    let encoding = encoding_name(tokenizer);
    let bpe = tiktoken_rs::bpe_for_tokenizer(tokenizer)
        .map_err(|_| CodexAdapterError::TokenizerUnavailable("tiktoken singleton init"))?;
    let tokens = u64::try_from(bpe.count_ordinary(text))
        .map_err(|_| CodexAdapterError::TokenizerUnavailable("token count out of range"))?;
    Ok(CodexMeasuredTokens {
        tokens,
        encoding,
        result_digest: sha256_hex(result_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn measured_codex_mini_hello_world() -> TestResult {
        let first = measure_result_tokens("codex-mini", b"hello world")?;
        let second = measure_result_tokens("codex-mini", b"hello world")?;
        assert_eq!(first, second, "counting must be deterministic");
        assert_eq!(first.tokens(), 2);
        assert_eq!(first.encoding(), "o200k_base");
        assert_eq!(
            first.result_digest(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        Ok(())
    }

    #[test]
    fn owner_mapping_per_variant() -> TestResult {
        // Model strings resolve through the owner registry verbatim
        // (exact entries and documented prefixes); each asserts the
        // encoding the registry assigns, not a local guess.
        for (model, encoding) in [
            ("codex-mini", "o200k_base"),
            ("gpt-5.3-codex-spark", "o200k_base"),
            ("gpt-4", "cl100k_base"),
            ("gpt-oss-20b", "o200k_harmony"),
            ("text-davinci-003", "p50k_base"),
            ("davinci", "r50k_base"),
            ("gpt2", "gpt2"),
        ] {
            let measured = measure_result_tokens(model, b"hello world")?;
            assert_eq!(measured.encoding(), encoding, "mapping: {model}");
            assert_eq!(measured.tokens(), 2);
        }
        Ok(())
    }

    #[test]
    fn measured_pangram_per_encoding() -> TestResult {
        for (model, tokens) in [("codex-mini", 20), ("gpt-4", 20), ("gpt-oss-20b", 20)] {
            let measured = measure_result_tokens(
                model,
                b"The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs!",
            )?;
            assert_eq!(measured.tokens(), tokens, "pangram: {model}");
        }
        Ok(())
    }

    #[test]
    fn special_token_text_counted_as_data() -> TestResult {
        // Ordinary counting: a special-token spelling inside result bytes
        // tokenizes as literal characters (9), never collapses to the
        // 3-token special form control tokens would take.
        let measured = measure_result_tokens("codex-mini", b"a<|endoftext|>b")?;
        assert_eq!(measured.tokens(), 9);
        assert_eq!(measured.encoding(), "o200k_base");
        Ok(())
    }

    #[test]
    fn withhold_unmapped_model() -> TestResult {
        // Documented registry gaps plus future-model shapes withhold with
        // the exact model echoed; nothing is guessed by prefix or fallback.
        for model in ["o4", "gpt-6", "not-a-model"] {
            match measure_result_tokens(model, b"hello world") {
                Err(CodexAdapterError::UnknownTokenizerModel { model_id }) => {
                    assert_eq!(model_id, model);
                }
                other => panic!("must withhold {model}: {other:?}"),
            }
        }
        Ok(())
    }

    #[test]
    fn withhold_non_utf8_bytes() -> TestResult {
        assert!(matches!(
            measure_result_tokens("codex-mini", b"\xff\xfe\x00binary"),
            Err(CodexAdapterError::UncountableBytes)
        ));
        Ok(())
    }
}
