//! Canonical encoding and identity-visible digests.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Canonical bytes sort object keys so wire order never changes identity.
//! [`SemanticSequence`] keeps item order identity-visible: order changes the
//! digest. [`canonical_digest_sorted`] offers the order-invariant set view.
//! Hostile inputs are bounded and panic-free: oversize or control-char text
//! is rejected with [`ContractViolation::Malformed`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractViolation;

/// Maximum accepted text length for a single validated item (1 MiB).
pub const MAX_ITEM_BYTES: usize = 1024 * 1024;

/// Separator used when joining sequence items before hashing.
const JOIN_SEPARATOR: &str = "\u{1f}";

/// Returns deterministic canonical JSON bytes, failing closed on serialization errors.
pub fn canonical_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ContractViolation> {
    eliot_contracts::canonical_json_bytes(value).map_err(|err| ContractViolation::Malformed {
        field: "canonical_bytes",
        reason: err.to_string(),
    })
}

/// Returns the lowercase hex SHA-256 digest of `bytes`.
pub fn digest_hex(bytes: &[u8]) -> String {
    eliot_contracts::sha256_hex(bytes)
}

/// Validates bounded, printable text.
///
/// Rejects empty input only when the caller requires non-empty text via
/// `require_non_empty`; always rejects input longer than
/// [`MAX_ITEM_BYTES`] bytes and input containing control characters.
///
/// # Errors
///
/// Returns [`ContractViolation::Malformed`] for oversize input, control
/// characters, or blank input when `require_non_empty` is set.
pub fn validate_text(
    field: &'static str,
    value: &str,
    require_non_empty: bool,
) -> Result<(), ContractViolation> {
    if value.len() > MAX_ITEM_BYTES {
        return Err(ContractViolation::Malformed {
            field,
            reason: format!("input exceeds {MAX_ITEM_BYTES} bytes"),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ContractViolation::Malformed {
            field,
            reason: "input contains control characters".to_owned(),
        });
    }
    if require_non_empty && value.trim().is_empty() {
        return Err(ContractViolation::Malformed {
            field,
            reason: "input must be non-blank".to_owned(),
        });
    }
    Ok(())
}

/// An order-sensitive semantic sequence with an identity-visible digest.
///
/// The digest is computed over items in order: reordering items changes the
/// digest. For the order-invariant set view use
/// [`canonical_digest_sorted`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticSequence {
    /// Sequence items in identity order.
    pub items: Vec<String>,
    /// Hex digest over the ordered items.
    pub digest: String,
}

impl SemanticSequence {
    /// Builds a sequence, computing the digest over items in order.
    #[must_use]
    pub fn new(items: Vec<String>) -> Self {
        let digest = digest_join(&items);
        Self { items, digest }
    }

    /// Builds a sequence with bounds enforced on every item.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Malformed`] when any item is oversize or
    /// contains control characters.
    pub fn try_new(items: Vec<String>) -> Result<Self, ContractViolation> {
        for item in &items {
            validate_text("sequence_item", item, false)?;
        }
        let total: usize = items.iter().map(String::len).sum();
        if total > MAX_ITEM_BYTES {
            return Err(ContractViolation::Malformed {
                field: "sequence_items",
                reason: format!("sequence exceeds {MAX_ITEM_BYTES} bytes"),
            });
        }
        Ok(Self::new(items))
    }
}

/// Returns the digest over items in the given order (order matters).
fn digest_join(items: &[String]) -> String {
    digest_hex(items.join(JOIN_SEPARATOR).as_bytes())
}

/// Returns the digest over items in sorted order (order-invariant set view).
///
/// Insertion order never changes the result: the same set of items always
/// yields the same digest.
#[must_use]
pub fn canonical_digest_sorted(items: &[String]) -> String {
    let mut sorted: Vec<&String> = items.iter().collect();
    sorted.sort();
    let joined: String = sorted
        .iter()
        .map(|item| item.as_str())
        .collect::<Vec<&str>>()
        .join(JOIN_SEPARATOR);
    digest_hex(joined.as_bytes())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // WORK_UNIT_CASE: 578/41
    #[test]
    fn marker_41_canonical_bytes_invariant_under_irrelevant_order() {
        let mut first: HashMap<String, String> = HashMap::new();
        first.insert("b".to_owned(), "2".to_owned());
        first.insert("a".to_owned(), "1".to_owned());
        let mut second: HashMap<String, String> = HashMap::new();
        second.insert("a".to_owned(), "1".to_owned());
        second.insert("b".to_owned(), "2".to_owned());
        assert_eq!(canonical_bytes(&first), canonical_bytes(&second));
        assert_eq!(
            digest_hex(&canonical_bytes(&first).expect("fixture serializes")),
            digest_hex(&canonical_bytes(&second).expect("fixture serializes"))
        );

        let one = vec!["x".to_owned(), "y".to_owned()];
        let two = vec!["y".to_owned(), "x".to_owned()];
        assert_eq!(canonical_digest_sorted(&one), canonical_digest_sorted(&two));
    }

    // WORK_UNIT_CASE: 578/42
    #[test]
    fn marker_42_semantic_sequence_order_is_identity_visible() {
        let first = SemanticSequence::new(vec!["a".to_owned(), "b".to_owned()]);
        let second = SemanticSequence::new(vec!["b".to_owned(), "a".to_owned()]);
        assert_ne!(first.digest, second.digest);
        assert_eq!(first.items, vec!["a".to_owned(), "b".to_owned()]);
    }

    // WORK_UNIT_CASE: 578/43
    #[test]
    fn marker_43_hostile_inputs_bounded_and_panic_free() {
        let hostile: Vec<String> = vec![
            String::new(),
            "   ".to_owned(),
            "\u{0}null byte".to_owned(),
            "tab\there".to_owned(),
            "newline\nhere".to_owned(),
            "a".repeat(MAX_ITEM_BYTES + 1),
            "z".repeat(MAX_ITEM_BYTES),
            "emoji 🦀 ok".to_owned(),
        ];
        for input in &hostile {
            let bytes = canonical_bytes(&input).expect("hostile input still serializes");
            assert!(!bytes.is_empty() || input.is_empty());
            let digest = digest_hex(input.as_bytes());
            assert_eq!(digest.len(), 64);
            let text = validate_text("hostile", input, false);
            if input.len() > MAX_ITEM_BYTES || input.chars().any(char::is_control) {
                assert!(
                    matches!(text, Err(ContractViolation::Malformed { .. })),
                    "hostile input must be rejected"
                );
            } else {
                assert!(text.is_ok());
            }
            let sequence = SemanticSequence::try_new(vec![input.clone()]);
            if input.len() > MAX_ITEM_BYTES || input.chars().any(char::is_control) {
                assert!(sequence.is_err(), "hostile item must be rejected");
            } else {
                assert!(sequence.is_ok());
            }
        }
        let oversize = vec!["q".repeat(MAX_ITEM_BYTES + 1)];
        assert!(matches!(
            SemanticSequence::try_new(oversize),
            Err(ContractViolation::Malformed { .. })
        ));
        let bad_key: HashMap<Vec<u8>, u8> = HashMap::from([(vec![1_u8], 2_u8)]);
        assert!(
            matches!(
                canonical_bytes(&bad_key),
                Err(ContractViolation::Malformed { .. })
            ),
            "non-string map keys must fail closed, never empty vec"
        );
    }
}
