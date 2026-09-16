use std::{fmt, num::NonZeroU64};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

use crate::{canonical_json_bytes, sha256_hex};

const DIGEST_DOMAIN_SEPARATOR: &str = "eliot.foundation.epoch-id.v1";

/// A validation or migration failure in the lineage-aware epoch contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EpochContractError {
    #[error("INVALID_LINEAGE_ID")]
    InvalidLineageId,
    #[error("ZERO_SEQUENCE")]
    ZeroSequence,
    #[error("SEQUENCE_OVERFLOW")]
    SequenceOverflow,
    #[error("INVALID_GENESIS")]
    InvalidGenesis,
    #[error("PARENT_LINEAGE_MISMATCH")]
    ParentLineageMismatch,
    #[error("NOT_DIRECT_CHILD")]
    NotDirectChild,
    #[error("SERIALIZATION_FAILURE")]
    SerializationFailure,
}

/// The lowercase hexadecimal SHA-256 identity of an epoch value.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[schemars(transparent)]
#[serde(transparent)]
pub struct LowercaseSha256(String);

impl LowercaseSha256 {
    /// Returns the canonical lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LowercaseSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LowercaseSha256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(de::Error::custom("digest must be lowercase SHA-256 hex"));
        }
        Ok(Self(value))
    }
}

/// A validated, opaque Host/recovery lineage identity.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[schemars(transparent)]
#[serde(transparent)]
pub struct EpochLineageId(String);

impl EpochLineageId {
    /// Constructs a canonical lowercase hyphenated UUID identity.
    pub fn new(canonical_uuid_text: impl AsRef<str>) -> Result<Self, EpochContractError> {
        let value = canonical_uuid_text.as_ref();
        if value.len() != 36
            || !value.is_ascii()
            || ![8, 13, 18, 23]
                .into_iter()
                .all(|index| value.as_bytes()[index] == b'-')
            || !value.bytes().enumerate().all(|(index, byte)| {
                [8, 13, 18, 23].contains(&index) || matches!(byte, b'0'..=b'9' | b'a'..=b'f')
            })
        {
            return Err(EpochContractError::InvalidLineageId);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the canonical lineage spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EpochLineageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EpochLineageId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A lineage-aware authority identity.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EpochId {
    pub lineage_id: EpochLineageId,
    pub sequence: NonZeroU64,
}

impl EpochId {
    /// Constructs an epoch without exposing scalar coercion.
    pub fn new(
        lineage_id: EpochLineageId,
        sequence: NonZeroU64,
    ) -> Result<Self, EpochContractError> {
        Ok(Self {
            lineage_id,
            sequence,
        })
    }

    /// Exact authority match: true only when `lineage_id` and `sequence`
    /// are both equal (contract `types.EpochId` exact-tuple rule; I6.10
    /// exact-match: equal sequences from different lineages are unrelated).
    #[must_use]
    pub fn is_same_authority(&self, expected: &Self) -> bool {
        self.lineage_id == expected.lineage_id && self.sequence == expected.sequence
    }

    /// Direct-child check: true only when the lineage is equal and
    /// `self.sequence == parent.sequence + 1` (contract
    /// `types.EpochTransition` one-step rule; I6.10 exact-match).
    /// Overflow-closed: `checked_add` failure returns false, so a genesis
    /// `sequence == 1` epoch is never a child.
    #[must_use]
    pub fn is_direct_child_of(&self, parent: &Self) -> bool {
        self.lineage_id == parent.lineage_id
            && parent.sequence.get().checked_add(1) == Some(self.sequence.get())
    }

    /// Returns the relation of this epoch to another validated epoch.
    #[must_use]
    pub fn relation_to(&self, other: &Self) -> EpochRelation {
        if self.lineage_id != other.lineage_id {
            return EpochRelation::UnrelatedLineage;
        }
        if self.sequence == other.sequence {
            return EpochRelation::Same;
        }
        if self.sequence.get().checked_add(1) == Some(other.sequence.get()) {
            return EpochRelation::DirectChild;
        }
        if other.sequence.get().checked_add(1) == Some(self.sequence.get()) {
            return EpochRelation::DirectParent;
        }
        if self.sequence < other.sequence {
            EpochRelation::SameLineageOlder
        } else {
            EpochRelation::SameLineageNewer
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochIdWire {
    lineage_id: EpochLineageId,
    sequence: u64,
}

impl<'de> Deserialize<'de> for EpochId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EpochIdWire::deserialize(deserializer)?;
        let sequence = NonZeroU64::new(wire.sequence)
            .ok_or(EpochContractError::ZeroSequence)
            .map_err(de::Error::custom)?;
        Self::new(wire.lineage_id, sequence).map_err(de::Error::custom)
    }
}

/// The relation between two epochs in the same or different lineages.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpochRelation {
    Same,
    DirectChild,
    DirectParent,
    SameLineageOlder,
    SameLineageNewer,
    UnrelatedLineage,
}

/// An explicit current/parent authority transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EpochTransition {
    pub current: EpochId,
    pub parent: Option<EpochId>,
}

impl EpochTransition {
    /// Creates a genesis transition at sequence one.
    pub fn genesis(lineage_id: EpochLineageId) -> Self {
        Self {
            current: EpochId {
                lineage_id,
                sequence: NonZeroU64::MIN,
            },
            parent: None,
        }
    }

    /// Creates the one-step child transition for a parent epoch.
    pub fn direct_child(parent: &EpochId) -> Result<Self, EpochContractError> {
        let sequence = parent
            .sequence
            .get()
            .checked_add(1)
            .ok_or(EpochContractError::SequenceOverflow)?;
        let current = EpochId::new(
            parent.lineage_id.clone(),
            NonZeroU64::new(sequence).ok_or(EpochContractError::ZeroSequence)?,
        )?;
        Ok(Self {
            current,
            parent: Some(parent.clone()),
        })
    }

    /// Validates genesis and explicit one-step parent invariants.
    pub fn validate(&self) -> Result<(), EpochContractError> {
        match &self.parent {
            None if self.current.sequence.get() == 1 => Ok(()),
            None => Err(EpochContractError::InvalidGenesis),
            Some(parent) if self.current.sequence.get() == 1 => {
                if parent.lineage_id == self.current.lineage_id {
                    Err(EpochContractError::InvalidGenesis)
                } else {
                    Err(EpochContractError::ParentLineageMismatch)
                }
            }
            Some(parent) if parent.lineage_id != self.current.lineage_id => {
                Err(EpochContractError::ParentLineageMismatch)
            }
            Some(parent) => {
                let expected = parent
                    .sequence
                    .get()
                    .checked_add(1)
                    .ok_or(EpochContractError::SequenceOverflow)?;
                if self.current.sequence.get() == expected {
                    Ok(())
                } else {
                    Err(EpochContractError::NotDirectChild)
                }
            }
        }
    }

    /// Advancement check: true only when the transition validates (contract
    /// `types.EpochTransition` genesis/direct-child/lineage rules; I6.10
    /// exact-match) and the explicit parent equals `prior`.
    #[must_use]
    pub fn advances(&self, prior: &EpochId) -> bool {
        self.validate().is_ok() && self.parent.as_ref() == Some(prior)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochTransitionWire {
    current: EpochId,
    parent: Option<EpochId>,
}

impl<'de> Deserialize<'de> for EpochTransition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EpochTransitionWire::deserialize(deserializer)?;
        let transition = Self {
            current: wire.current,
            parent: wire.parent,
        };
        transition.validate().map_err(de::Error::custom)?;
        Ok(transition)
    }
}

#[derive(Serialize)]
struct EpochDigestInput<'a> {
    domain_separator: &'static str,
    lineage_id: &'a EpochLineageId,
    sequence: NonZeroU64,
}

/// Computes the canonical digest over the domain, lineage, and sequence.
pub fn epoch_identity_digest(epoch_id: &EpochId) -> Result<LowercaseSha256, EpochContractError> {
    let input = EpochDigestInput {
        domain_separator: DIGEST_DOMAIN_SEPARATOR,
        lineage_id: &epoch_id.lineage_id,
        sequence: epoch_id.sequence,
    };
    let bytes =
        canonical_json_bytes(&input).map_err(|_| EpochContractError::SerializationFailure)?;
    Ok(LowercaseSha256(sha256_hex(&bytes)))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";

    fn lineage(value: &str) -> EpochLineageId {
        EpochLineageId::new(value).expect("valid lineage")
    }

    fn epoch(value: &str, sequence: u64) -> EpochId {
        EpochId::new(
            lineage(value),
            NonZeroU64::new(sequence).expect("nonzero sequence"),
        )
        .expect("valid epoch")
    }

    #[test]
    fn lineage_validation_and_relations_are_not_scalar_ordering() {
        assert!(EpochLineageId::new(LINEAGE_A.to_uppercase()).is_err());
        assert!(EpochLineageId::new(LINEAGE_A.replace('-', "")).is_err());
        assert_eq!(lineage(LINEAGE_A).as_str(), LINEAGE_A);
        assert_eq!(
            epoch(LINEAGE_A, 100).relation_to(&epoch(LINEAGE_B, 1)),
            EpochRelation::UnrelatedLineage
        );
        assert_eq!(
            epoch(LINEAGE_A, 1).relation_to(&epoch(LINEAGE_A, 2)),
            EpochRelation::DirectChild
        );
    }

    #[test]
    fn transitions_require_explicit_valid_lineage_parent() {
        EpochTransition::genesis(lineage(LINEAGE_A))
            .validate()
            .expect("valid genesis");
        assert!(matches!(
            EpochTransition {
                current: epoch(LINEAGE_A, 2),
                parent: None,
            }
            .validate(),
            Err(EpochContractError::InvalidGenesis)
        ));
        assert!(matches!(
            EpochTransition {
                current: epoch(LINEAGE_A, 2),
                parent: Some(epoch(LINEAGE_B, 1)),
            }
            .validate(),
            Err(EpochContractError::ParentLineageMismatch)
        ));
        assert_eq!(
            EpochTransition::direct_child(&epoch(LINEAGE_A, u64::MAX)),
            Err(EpochContractError::SequenceOverflow)
        );
    }

    #[test]
    fn digest_is_stable_and_lineage_sensitive() {
        let first = epoch_identity_digest(&epoch(LINEAGE_A, 1)).expect("digest");
        assert_eq!(
            first.as_str(),
            "96c573f14405b0a0f8d51398fd139046e815f7816164df7663792f57933c465f"
        );
        assert_eq!(
            first,
            epoch_identity_digest(&epoch(LINEAGE_A, 1)).expect("digest")
        );
        assert_ne!(
            first,
            epoch_identity_digest(&epoch(LINEAGE_A, 2)).expect("digest")
        );
        assert_ne!(
            first,
            epoch_identity_digest(&epoch(LINEAGE_B, 1)).expect("digest")
        );
    }

    #[test]
    fn all_decoded_epoch_structures_reject_unknown_or_invalid_fields() {
        assert!(
            serde_json::from_value::<EpochId>(serde_json::json!({
                "lineage_id": LINEAGE_A,
                "sequence": 0,
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<EpochId>(serde_json::json!({
                "lineage_id": LINEAGE_A,
                "sequence": 1,
                "unknown": true,
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<EpochTransition>(serde_json::json!({
                "current": {"lineage_id": LINEAGE_A, "sequence": 2},
                "parent": null,
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<EpochRelation>(serde_json::json!("FUTURE")).is_err());
    }

    #[test]
    fn same_authority_requires_exact_tuple_match() {
        assert!(epoch(LINEAGE_A, 3).is_same_authority(&epoch(LINEAGE_A, 3)));
        assert!(!epoch(LINEAGE_A, 3).is_same_authority(&epoch(LINEAGE_A, 4)));
        assert!(!epoch(LINEAGE_A, 3).is_same_authority(&epoch(LINEAGE_B, 3)));
        assert!(!epoch(LINEAGE_A, 3).is_same_authority(&epoch(LINEAGE_B, 9)));
    }

    #[test]
    fn direct_child_requires_same_lineage_plus_one() {
        assert!(epoch(LINEAGE_A, 2).is_direct_child_of(&epoch(LINEAGE_A, 1)));
        assert!(!epoch(LINEAGE_A, 1).is_direct_child_of(&epoch(LINEAGE_A, 1)));
        assert!(!epoch(LINEAGE_A, 3).is_direct_child_of(&epoch(LINEAGE_A, 1)));
        assert!(!epoch(LINEAGE_A, 1).is_direct_child_of(&epoch(LINEAGE_A, 2)));
        assert!(!epoch(LINEAGE_B, 2).is_direct_child_of(&epoch(LINEAGE_A, 1)));
        assert!(!epoch(LINEAGE_A, 1).is_direct_child_of(&epoch(LINEAGE_A, u64::MAX)));
    }

    #[test]
    fn advances_requires_valid_transition_with_matching_prior() {
        let prior = epoch(LINEAGE_A, 1);
        let direct = EpochTransition::direct_child(&prior).expect("direct child");
        assert!(direct.advances(&prior));
        assert!(!EpochTransition::genesis(lineage(LINEAGE_A)).advances(&epoch(LINEAGE_A, 1)));
        assert!(!direct.advances(&epoch(LINEAGE_A, 2)));
        assert!(
            !EpochTransition {
                current: epoch(LINEAGE_A, 3),
                parent: Some(epoch(LINEAGE_A, 1)),
            }
            .advances(&epoch(LINEAGE_A, 1))
        );
    }
}
