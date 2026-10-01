//! Codex-route render-time token measurement (issue #1941 C6).
//!
//! Counts exact bytes with the route's actual tokenizer through the
//! owner-published `tiktoken` mappings. Authority is `OpenAI` `tiktoken`
//! `model.py` at version 0.13.0
//! (`https://github.com/openai/tiktoken/blob/0.13.0/tiktoken/model.py`);
//! the local registry (`tiktoken-rs` 0.12.0, exact pin) is its execution
//! engine, not its authority: the two tables were diffed field-by-field and
//! the ONLY divergences are community additions the owner never published —
//! the `gpt-5.` and `codex-mini` extra prefixes, plus `ft:` shapes beyond
//! the five owner `ft:` prefixes. [`owner_supported`] denies exactly that
//! delta, so an exact model string measures only when the OWNER mapping
//! covers it; everything else (unknown IDs, future `gpt-6` shapes,
//! community-only codex prefixes) withholds via
//! [`CodexAdapterError::UnknownTokenizerModel`]. A registry change on
//! either side arrives via version bump and re-opens this review; stale
//! state withholds, never over-measures.
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

/// Upstream `ft:` model prefixes documented in `OpenAI` `tiktoken` `model.py`
/// 0.13.0. Only these fine-tuned forms are owner-mapped; every other `ft:`
/// shape withholds even when stripping the prefix would resolve, because the
/// owner never published that mapping.
const UPSTREAM_FT_PREFIXES: [&str; 5] = [
    "ft:gpt-4o",
    "ft:gpt-4",
    "ft:gpt-3.5-turbo",
    "ft:davinci-002",
    "ft:babbage-002",
];

/// Whether the exact model string is covered by the OWNER mapping
/// (`OpenAI` `tiktoken` `model.py` 0.13.0), as opposed to community-only
/// additions in `tiktoken-rs` 0.12.0.
///
/// Mechanically verified delta (pinned sources diffed field-by-field):
/// the community crate adds exactly two prefix rules absent upstream —
/// `gpt-5.` and `codex-mini` — and resolves all other `ft:` shapes by
/// prefix-stripping where upstream maps only the five `ft:` prefixes
/// above. Everything else in the two tables is identical. Denying exactly
/// that delta makes this gate equivalent to the owner mapping for the
/// pinned pair; any registry change on either side arrives via a version
/// bump, which re-opens this review (stale state withholds, never
/// over-measures).
fn owner_supported(model_id: &str) -> bool {
    if model_id.starts_with("ft:") {
        return UPSTREAM_FT_PREFIXES
            .iter()
            .any(|prefix| model_id.starts_with(prefix));
    }
    if model_id.starts_with("codex-mini") || model_id.starts_with("gpt-5.") {
        return false;
    }
    true
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
    // Owner gate first: community-only mappings (tiktoken-rs extras absent
    // from upstream model.py) withhold here even though the local registry
    // would resolve them. Unknown-to-both registries withholds below.
    if !owner_supported(model_id) {
        return Err(CodexAdapterError::UnknownTokenizerModel {
            model_id: model_id.to_owned(),
        });
    }
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
