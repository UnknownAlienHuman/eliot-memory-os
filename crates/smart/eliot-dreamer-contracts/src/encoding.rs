//! Canonical encoding and identity-visible digests.
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Canonical bytes sort object keys so wire order never changes identity.
//! [`SemanticSequence`] keeps item order identity-visible: order changes the
//! digest. [`try_canonical_digest_sorted`] offers the order-invariant set view.
//! Hostile inputs are bounded and panic-free: oversize or control-char text
//! is rejected with [`ContractViolation::Malformed`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ContractViolation, check_vec_bound};

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
/// Rejects blank-if-required, oversize, or control-char input.
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
/// Reordering items changes the digest; for the order-invariant set view use
/// [`try_canonical_digest_sorted`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, try_from = "RawSequence")]
pub struct SemanticSequence {
    /// Sequence items in identity order.
    items: Vec<String>,
    /// Hex digest over the ordered items.
    digest: String,
}

impl SemanticSequence {
    /// Builds a sequence, computing the digest over items in order.
    #[must_use]
    fn new(items: Vec<String>) -> Self {
        let digest = digest_join(&items);
        Self { items, digest }
    }

    /// Builds a sequence with bounds enforced on every item.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Malformed`] or [`ContractViolation::OutOfBounds`].
    pub fn try_new(items: Vec<String>) -> Result<Self, ContractViolation> {
        check_sequence_bounds(&items)?;
        Ok(Self::new(items))
    }

    /// Validates item bounds, join budget, and digest agreement.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Malformed`] or [`ContractViolation::OutOfBounds`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_sequence_bounds(&self.items)?;
        if self.digest == digest_join(&self.items) {
            return Ok(());
        }
        Err(ContractViolation::Malformed {
            field: "sequence_digest",
            reason: "digest does not match items".to_owned(),
        })
    }
}

fn check_sequence_bounds(items: &[String]) -> Result<(), ContractViolation> {
    let mut joined = items.len().saturating_sub(1);
    for item in items {
        validate_text("sequence_item", item, false)?;
        joined = joined.saturating_add(item.len());
    }
    check_vec_bound(items.len(), 1024, "sequence_items")?;
    if joined > MAX_ITEM_BYTES {
        return Err(ContractViolation::Malformed {
            field: "sequence_items",
            reason: format!("sequence exceeds {MAX_ITEM_BYTES} bytes"),
        });
    }
    Ok(())
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawSequence {
    items: Vec<String>,
    digest: String,
}

impl TryFrom<RawSequence> for SemanticSequence {
    type Error = ContractViolation;
    fn try_from(raw: RawSequence) -> Result<Self, Self::Error> {
        let sequence = Self {
            items: raw.items,
            digest: raw.digest,
        };
        sequence.validate()?;
        Ok(sequence)
    }
}

fn digest_join(items: &[String]) -> String {
    digest_hex(items.join(JOIN_SEPARATOR).as_bytes())
}

/// Returns the digest over items in sorted order (order-invariant set view).
pub fn try_canonical_digest_sorted(items: &[String]) -> Result<String, ContractViolation> {
    check_sequence_bounds(items)?;
    let mut sorted = items.to_vec();
    sorted.sort();
    Ok(digest_join(&sorted))
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
        let first_digest = digest_hex(&canonical_bytes(&first).expect("fixture serializes"));
        let second_digest = digest_hex(&canonical_bytes(&second).expect("fixture serializes"));
        assert_eq!(first_digest, second_digest);

        let one = vec!["x".to_owned(), "y".to_owned()];
        let two = vec!["y".to_owned(), "x".to_owned()];
        let sorted_one = try_canonical_digest_sorted(&one).expect("bounded");
        let sorted_two = try_canonical_digest_sorted(&two).expect("bounded");
        assert_eq!(sorted_one, sorted_two);
        assert!(try_canonical_digest_sorted(&vec!["a".to_owned(); 1024]).is_ok());
        assert!(matches!(
            try_canonical_digest_sorted(&vec!["a".to_owned(); 1025]),
            Err(ContractViolation::OutOfBounds { .. })
        ));
        let wide = vec!["a".repeat(1024); 1024];
        assert!(matches!(
            try_canonical_digest_sorted(&wide),
            Err(ContractViolation::Malformed { .. })
        ));
        assert!(matches!(
            SemanticSequence::try_new(wide),
            Err(ContractViolation::Malformed { .. })
        ));
    }

    // WORK_UNIT_CASE: 578/42
    #[test]
    fn marker_42_semantic_sequence_order_is_identity_visible() {
        let first = SemanticSequence::try_new(vec!["a".to_owned(), "b".to_owned()]).expect("ok");
        let second = SemanticSequence::try_new(vec!["b".to_owned(), "a".to_owned()]).expect("ok");
        assert_ne!(first.digest, second.digest);
        assert_eq!(first.items, vec!["a".to_owned(), "b".to_owned()]);
        assert!(SemanticSequence::try_new(Vec::new()).is_ok());
        assert!(SemanticSequence::try_new(vec!["a".to_owned(); 1024]).is_ok());
        assert!(matches!(
            SemanticSequence::try_new(vec!["a".to_owned(); 1025]),
            Err(ContractViolation::OutOfBounds { .. })
        ));
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
            assert_eq!(digest_hex(input.as_bytes()).len(), 64);
            let bad = input.len() > MAX_ITEM_BYTES || input.chars().any(char::is_control);
            let text = validate_text("hostile", input, false);
            assert_eq!(
                bad,
                matches!(text, Err(ContractViolation::Malformed { .. }))
            );
            assert_eq!(bad, SemanticSequence::try_new(vec![input.clone()]).is_err());
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
        let hostile_items = vec!["\u{0}".to_owned(), "x".repeat(MAX_ITEM_BYTES + 1)];
        assert!(try_canonical_digest_sorted(&hostile_items).is_err());
        let big = vec!["b".repeat(600 * 1024); 2];
        let built = SemanticSequence::try_new(big.clone());
        assert!(matches!(built, Err(ContractViolation::Malformed { .. })));
        let sorted = try_canonical_digest_sorted(&big);
        assert!(matches!(sorted, Err(ContractViolation::Malformed { .. })));
        let mixed = vec!["ok".to_owned(), "bad\u{0}".to_owned()];
        assert!(try_canonical_digest_sorted(&mixed).is_err());
        assert!(matches!(
            SemanticSequence::try_new(mixed),
            Err(ContractViolation::Malformed { .. })
        ));
        let many = vec!["c".to_owned(); 1025];
        assert!(matches!(
            try_canonical_digest_sorted(&many),
            Err(ContractViolation::OutOfBounds { .. })
        ));
        let good = SemanticSequence::try_new(vec!["a".to_owned()]).expect("ok");
        let json = serde_json::to_string(&good).expect("serializes");
        assert_eq!(
            serde_json::from_str::<SemanticSequence>(&json).expect("roundtrip"),
            good
        );
        let tampered = json.replace(&good.digest, &"0".repeat(64));
        assert!(serde_json::from_str::<SemanticSequence>(&tampered).is_err());
        let extra = json.replace('}', r#","extra":1}"#);
        assert!(serde_json::from_str::<SemanticSequence>(&extra).is_err());
        digest_flood_probe();
    }

    fn digest_flood_probe() {
        let fence = crate::registry::fence();
        let hex = eliot_contracts::sha256_hex(b"model");
        let receipt = crate::draft::valid_receipt(&hex, fence.clone());
        let mut payload = crate::curation::sample_payload(crate::curation::CurationKind::Merge);
        if let crate::curation::CurationPayload::Merge(inner) = &mut payload {
            let mut targets = vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()];
            targets.extend((0..1022).map(|i| format!("t-{i:04}")));
            inner.target_evidence.targets = targets;
            let flood: Vec<String> = (0..1024).map(|i| format!("e-{i:04}")).collect();
            inner.target_evidence.evidence_refs = flood;
        }
        let item = crate::draft::ValidatedCurationItem {
            receipt,
            kind_spelling: "merge".to_owned(),
            family_spelling: "structure_repair".to_owned(),
            payload,
            denominator: crate::registry::TargetDenominator {
                mode: crate::registry::AtomicityMode::AllOrNothing,
                members: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
                expected_total: 3,
            },
            source_digest: eliot_contracts::sha256_hex(b"source"),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: fence,
            job_digest: "d".repeat(64),
            requester: crate::job::Requester {
                origin: crate::job::RequesterOrigin::Human,
                principal: "alice".to_owned(),
                session: None,
            },
            budget_note: "n".repeat(2 * 1024 * 1024),
        };
        let grounded = crate::draft::GroundedDreamDraft {
            schema_version: 1,
            job_id: "job-1".to_owned(),
            draft_digest: hex,
            residues: vec![crate::draft::ClaimResidue {
                claim: "c".to_owned(),
                state: crate::draft::SupportState::Partial,
                detail: "d".to_owned(),
            }],
            coverage_note: "covers".to_owned(),
        };
        let err = item.item_digest(&grounded).expect_err("flood must fail");
        assert!(matches!(
            err,
            crate::error::ContractViolation::OutOfBounds {
                field: "targets",
                ..
            }
        ));
    }
}
