use std::{fmt, num::NonZeroU64};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::Error as _};
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
    #[error("LEGACY_LINEAGE_EVIDENCE_MISSING")]
    LegacyLineageEvidenceMissing,
    #[error("LEGACY_LINEAGE_EVIDENCE_AMBIGUOUS")]
    LegacyLineageEvidenceAmbiguous,
    #[error("LEGACY_LINEAGE_EVIDENCE_CONFLICTED")]
    LegacyLineageEvidenceConflicted,
    #[error("LEGACY_ACTIVE_BINDING_FORBIDDEN")]
    LegacyActiveBindingForbidden,
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

/// A scalar epoch record retained only as migration evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyScalarEpoch {
    pub scalar_sequence: NonZeroU64,
    pub source_record_ref: String,
    pub source_contract_revision: String,
}

fn validate_legacy_text(value: &str) -> Result<(), EpochContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(EpochContractError::LegacyLineageEvidenceMissing);
    }
    Ok(())
}

impl LegacyScalarEpoch {
    /// Creates a provenance-bearing legacy scalar record.
    pub fn new(
        scalar_sequence: u64,
        source_record_ref: impl Into<String>,
        source_contract_revision: impl Into<String>,
    ) -> Result<Self, EpochContractError> {
        let scalar_sequence =
            NonZeroU64::new(scalar_sequence).ok_or(EpochContractError::ZeroSequence)?;
        let source_record_ref = source_record_ref.into();
        let source_contract_revision = source_contract_revision.into();
        validate_legacy_text(&source_record_ref)?;
        validate_legacy_text(&source_contract_revision)?;
        Ok(Self {
            scalar_sequence,
            source_record_ref,
            source_contract_revision,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyScalarEpochWire {
    scalar_sequence: u64,
    source_record_ref: String,
    source_contract_revision: String,
}

impl<'de> Deserialize<'de> for LegacyScalarEpoch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LegacyScalarEpochWire::deserialize(deserializer)?;
        Self::new(
            wire.scalar_sequence,
            wire.source_record_ref,
            wire.source_contract_revision,
        )
        .map_err(de::Error::custom)
    }
}

/// Explicit evidence states accepted by the legacy import boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LegacyEpochEvidence {
    Bound {
        installation_identity: String,
        host_lineage: EpochLineageId,
        source_record_identity: String,
        migration_receipt: String,
    },
    Missing,
    Ambiguous,
    Conflicted,
    #[schemars(skip)]
    ActiveBinding(EpochId),
}

impl Serialize for LegacyEpochEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Bound {
                installation_identity,
                host_lineage,
                source_record_identity,
                migration_receipt,
            } => serializer.serialize_newtype_variant(
                "LegacyEpochEvidence",
                0,
                "BOUND",
                &LegacyBoundEvidenceOutput {
                    installation_identity,
                    host_lineage,
                    source_record_identity,
                    migration_receipt,
                },
            ),
            Self::Missing => serializer.serialize_unit_variant("LegacyEpochEvidence", 1, "MISSING"),
            Self::Ambiguous => {
                serializer.serialize_unit_variant("LegacyEpochEvidence", 2, "AMBIGUOUS")
            }
            Self::Conflicted => {
                serializer.serialize_unit_variant("LegacyEpochEvidence", 3, "CONFLICTED")
            }
            Self::ActiveBinding(_) => Err(S::Error::custom(
                EpochContractError::LegacyActiveBindingForbidden,
            )),
        }
    }
}

#[derive(Serialize)]
struct LegacyBoundEvidenceOutput<'a> {
    installation_identity: &'a str,
    host_lineage: &'a EpochLineageId,
    source_record_identity: &'a str,
    migration_receipt: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyBoundEvidenceWire {
    installation_identity: String,
    host_lineage: EpochLineageId,
    source_record_identity: String,
    migration_receipt: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum LegacyEpochEvidenceWire {
    Bound(LegacyBoundEvidenceWire),
    Missing,
    Ambiguous,
    Conflicted,
}

impl<'de> Deserialize<'de> for LegacyEpochEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match LegacyEpochEvidenceWire::deserialize(deserializer)? {
            LegacyEpochEvidenceWire::Bound(wire) => {
                for value in [
                    &wire.installation_identity,
                    &wire.source_record_identity,
                    &wire.migration_receipt,
                ] {
                    validate_legacy_text(value).map_err(de::Error::custom)?;
                }
                Ok(Self::Bound {
                    installation_identity: wire.installation_identity,
                    host_lineage: wire.host_lineage,
                    source_record_identity: wire.source_record_identity,
                    migration_receipt: wire.migration_receipt,
                })
            }
            LegacyEpochEvidenceWire::Missing => Ok(Self::Missing),
            LegacyEpochEvidenceWire::Ambiguous => Ok(Self::Ambiguous),
            LegacyEpochEvidenceWire::Conflicted => Ok(Self::Conflicted),
        }
    }
}

/// The loss-visible result of importing a legacy scalar epoch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LegacyEpochImport {
    EvidenceBoundActive {
        epoch_id: EpochId,
        legacy: LegacyScalarEpoch,
        evidence: LegacyEpochEvidence,
    },
    HistoricalSuspended {
        legacy: LegacyScalarEpoch,
        evidence: LegacyEpochEvidence,
    },
    ManualRecoveryRequired {
        legacy: LegacyScalarEpoch,
        evidence: LegacyEpochEvidence,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveImportWire {
    epoch_id: EpochId,
    legacy: LegacyScalarEpoch,
    evidence: LegacyEpochEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NonActiveImportWire {
    legacy: LegacyScalarEpoch,
    evidence: LegacyEpochEvidence,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum LegacyEpochImportWire {
    EvidenceBoundActive(ActiveImportWire),
    HistoricalSuspended(NonActiveImportWire),
    ManualRecoveryRequired(NonActiveImportWire),
}

impl<'de> Deserialize<'de> for LegacyEpochImport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let requested = LegacyEpochImportWire::deserialize(deserializer)?;
        let (requested_active_epoch, legacy, evidence, requested_state) = match requested {
            LegacyEpochImportWire::EvidenceBoundActive(wire) => {
                (Some(wire.epoch_id), wire.legacy, wire.evidence, 0_u8)
            }
            LegacyEpochImportWire::HistoricalSuspended(wire) => {
                (None, wire.legacy, wire.evidence, 1_u8)
            }
            LegacyEpochImportWire::ManualRecoveryRequired(wire) => {
                (None, wire.legacy, wire.evidence, 2_u8)
            }
        };
        let imported = import_legacy_scalar_epoch(legacy, evidence).map_err(de::Error::custom)?;
        let valid_shape = match (&imported, requested_active_epoch.as_ref(), requested_state) {
            (Self::EvidenceBoundActive { epoch_id, .. }, Some(requested_epoch), 0) => {
                epoch_id == requested_epoch
            }
            (Self::HistoricalSuspended { .. }, None, 1)
            | (Self::ManualRecoveryRequired { .. }, None, 2) => true,
            _ => false,
        };
        if !valid_shape {
            return Err(de::Error::custom(
                EpochContractError::LegacyActiveBindingForbidden,
            ));
        }
        Ok(imported)
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

/// Imports a scalar epoch without ever defaulting to the current lineage.
pub fn import_legacy_scalar_epoch(
    input: LegacyScalarEpoch,
    evidence: LegacyEpochEvidence,
) -> Result<LegacyEpochImport, EpochContractError> {
    match &evidence {
        LegacyEpochEvidence::Bound {
            installation_identity,
            host_lineage,
            source_record_identity,
            migration_receipt,
        } => {
            validate_legacy_text(installation_identity)?;
            validate_legacy_text(source_record_identity)?;
            validate_legacy_text(migration_receipt)?;
            if source_record_identity != &input.source_record_ref {
                return Err(EpochContractError::LegacyLineageEvidenceConflicted);
            }
            let epoch_id = EpochId::new(host_lineage.clone(), input.scalar_sequence)?;
            Ok(LegacyEpochImport::EvidenceBoundActive {
                epoch_id,
                legacy: input,
                evidence,
            })
        }
        LegacyEpochEvidence::Missing => Ok(LegacyEpochImport::HistoricalSuspended {
            legacy: input,
            evidence,
        }),
        LegacyEpochEvidence::Ambiguous | LegacyEpochEvidence::Conflicted => {
            Ok(LegacyEpochImport::ManualRecoveryRequired {
                legacy: input,
                evidence,
            })
        }
        LegacyEpochEvidence::ActiveBinding(_) => {
            Err(EpochContractError::LegacyActiveBindingForbidden)
        }
    }
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

    fn legacy() -> LegacyScalarEpoch {
        LegacyScalarEpoch::new(7, "record-7", "legacy-v1").expect("legacy")
    }

    fn bound_evidence() -> LegacyEpochEvidence {
        LegacyEpochEvidence::Bound {
            installation_identity: "installation-1".to_owned(),
            host_lineage: lineage(LINEAGE_A),
            source_record_identity: "record-7".to_owned(),
            migration_receipt: "receipt-7".to_owned(),
        }
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
    fn canonical_import_is_the_only_active_promotion() {
        let active = import_legacy_scalar_epoch(legacy(), bound_evidence()).expect("active");
        assert!(matches!(
            active,
            LegacyEpochImport::EvidenceBoundActive { epoch_id, .. }
                if epoch_id.lineage_id.as_str() == LINEAGE_A && epoch_id.sequence.get() == 7
        ));
        assert!(matches!(
            import_legacy_scalar_epoch(legacy(), LegacyEpochEvidence::Missing),
            Ok(LegacyEpochImport::HistoricalSuspended { .. })
        ));
        assert!(matches!(
            import_legacy_scalar_epoch(legacy(), LegacyEpochEvidence::Ambiguous),
            Ok(LegacyEpochImport::ManualRecoveryRequired { .. })
        ));
        assert_eq!(
            import_legacy_scalar_epoch(
                legacy(),
                LegacyEpochEvidence::ActiveBinding(epoch(LINEAGE_A, 7))
            ),
            Err(EpochContractError::LegacyActiveBindingForbidden)
        );
        assert!(
            serde_json::to_value(LegacyEpochEvidence::ActiveBinding(epoch(LINEAGE_A, 7))).is_err()
        );
    }

    #[test]
    fn legacy_evidence_decode_rejects_unknown_future_and_malformed_wire() {
        let valid = serde_json::to_value(bound_evidence()).expect("encode");
        assert_eq!(
            serde_json::from_value::<LegacyEpochEvidence>(valid.clone()).expect("decode"),
            bound_evidence()
        );
        let malformed = [
            serde_json::json!({"BOUND": {"installation_identity": "", "host_lineage": LINEAGE_A, "source_record_identity": "record-7", "migration_receipt": "receipt-7"}}),
            serde_json::json!({"BOUND": {"installation_identity": "installation-1", "host_lineage": LINEAGE_A, "source_record_identity": "record-7", "migration_receipt": "receipt-7", "future": true}}),
            serde_json::json!({"FUTURE_EVIDENCE": {}}),
            serde_json::json!({"ACTIVE_BINDING": {"lineage_id": LINEAGE_A, "sequence": 0}}),
        ];
        for wire in malformed {
            assert!(serde_json::from_value::<LegacyEpochEvidence>(wire).is_err());
        }
    }

    #[test]
    fn legacy_import_decode_revalidates_canonical_state_and_roundtrips() {
        let values = [
            import_legacy_scalar_epoch(legacy(), bound_evidence()).expect("active"),
            import_legacy_scalar_epoch(legacy(), LegacyEpochEvidence::Missing).expect("suspended"),
            import_legacy_scalar_epoch(legacy(), LegacyEpochEvidence::Conflicted)
                .expect("manual recovery"),
        ];
        for value in values {
            let wire = serde_json::to_string(&value).expect("encode");
            assert_eq!(
                serde_json::from_str::<LegacyEpochImport>(&wire).expect("decode"),
                value
            );
        }

        let mut tampered = serde_json::to_value(
            import_legacy_scalar_epoch(legacy(), bound_evidence()).expect("active"),
        )
        .expect("encode");
        tampered["EVIDENCE_BOUND_ACTIVE"]["epoch_id"]["sequence"] = serde_json::json!(8);
        assert!(serde_json::from_value::<LegacyEpochImport>(tampered).is_err());

        let bypasses = [
            serde_json::json!({"EVIDENCE_BOUND_ACTIVE": {"epoch_id": {"lineage_id": LINEAGE_A, "sequence": 7}, "legacy": serde_json::to_value(legacy()).expect("legacy"), "evidence": "MISSING"}}),
            serde_json::json!({"HISTORICAL_SUSPENDED": {"legacy": serde_json::to_value(legacy()).expect("legacy"), "evidence": serde_json::to_value(bound_evidence()).expect("evidence")}}),
            serde_json::json!({"EVIDENCE_BOUND_ACTIVE": {"epoch_id": {"lineage_id": LINEAGE_A, "sequence": 7}, "legacy": serde_json::to_value(legacy()).expect("legacy"), "evidence": serde_json::json!({"ACTIVE_BINDING": {"lineage_id": LINEAGE_A, "sequence": 7}})}}),
            serde_json::json!({"FUTURE_IMPORT": {}}),
        ];
        for wire in bypasses {
            assert!(serde_json::from_value::<LegacyEpochImport>(wire).is_err());
        }
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
        assert!(
            serde_json::from_value::<LegacyScalarEpoch>(serde_json::json!({
                "scalar_sequence": 1,
                "source_record_ref": "record",
                "source_contract_revision": "v1",
                "unknown": true,
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<EpochRelation>(serde_json::json!("FUTURE")).is_err());
    }
}
