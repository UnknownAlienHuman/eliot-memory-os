//! Position identity: stable IDs plus canonical digests.
//!
//! Identity answers which proposition, claim, evidence set, manifest, source revision, lineage root, validity,
//! and predecessors are addressed; the digest answers which exact bytes were frozen. A digest is never an
//! identity, and derivations that merely restate raw input are rejected.
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{
    ContractError, MAX_SHORT_TEXT, check_frozen, shape_digest, validate_bounded_text,
};
#[macro_export]
macro_rules! position_id {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
        #[schemars(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_bounded_text(&value, $label, MAX_SHORT_TEXT)?;
                Ok(Self(value))
            }
            pub fn as_str(&self) -> &str { &self.0 }

            /// Consumes this identifier and returns its text.
            pub fn into_string(self) -> String { self.0 }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }
        impl FromStr for $name {
            type Err = ContractError;
            fn from_str(value: &str) -> Result<Self, Self::Err> { Self::new(value) }
        }
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer { serializer.serialize_str(&self.0) }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}
position_id!(
    /// Identity of one proposition addressed by an epistemic position.
    PropositionId,
    "proposition_id"
);
position_id!(
    /// Identity of one governed claim about a proposition.
    ClaimId,
    "claim_id"
);
position_id!(
    /// Identity of one frozen evidence set cited by a position.
    EvidenceSetId,
    "evidence_set_id"
);
position_id!(
    /// Identity of the allowed-reference manifest bounding a position.
    ManifestId,
    "manifest_id"
);
position_id!(
    /// Identity of one immutable source revision.
    SourceRevisionId,
    "source_revision_id"
);
position_id!(
    /// Identity of the lineage root a derivation traces back to.
    LineageRootId,
    "lineage_root_id"
);
position_id!(
    /// Identity of the validity window a position was frozen under.
    ValidityId,
    "validity_id"
);
position_id!(
    /// Identity of one predecessor position or record.
    PredecessorId,
    "predecessor_id"
);

/// The complete identity closure: predecessors form a set; `digest` covers every field but itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityBundle {
    /// Proposition under discussion.
    pub proposition: PropositionId,
    /// Governed claim identity for the proposition.
    pub claim: ClaimId,
    /// Frozen evidence set cited by the position.
    pub evidence_set: EvidenceSetId,
    /// Allowed-reference manifest bounding the position.
    pub manifest: ManifestId,
    /// Source revision the position was read from.
    pub source_revision: SourceRevisionId,
    /// Lineage root the position traces back to.
    pub lineage_root: LineageRootId,
    /// Validity window the position was frozen under.
    pub validity: ValidityId,
    /// Exact predecessors, retained even when superseded.
    pub predecessors: BTreeSet<PredecessorId>,
    /// Canonical digest of the identity shape, excluding this field.
    pub digest: String,
}
/// Named constructor arguments for [`IdentityBundle::new`].
/// Named fields block transposition; all members are typed ids.
#[derive(Clone, Debug)]
pub struct IdentityBundleParams {
    pub proposition: PropositionId,
    pub claim: ClaimId,
    pub evidence_set: EvidenceSetId,
    pub manifest: ManifestId,
    pub source_revision: SourceRevisionId,
    pub lineage_root: LineageRootId,
    pub validity: ValidityId,
    pub predecessors: BTreeSet<PredecessorId>,
}
impl IdentityBundle {
    pub fn new(params: IdentityBundleParams) -> Result<Self, ContractError> {
        if params.predecessors.len() > crate::error::MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "identity.predecessors",
            });
        }
        let mut bundle = Self {
            proposition: params.proposition,
            claim: params.claim,
            evidence_set: params.evidence_set,
            manifest: params.manifest,
            source_revision: params.source_revision,
            lineage_root: params.lineage_root,
            validity: params.validity,
            predecessors: params.predecessors,
            digest: String::new(),
        };
        bundle.digest = bundle.compute_digest()?;
        Ok(bundle)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.proposition,
            &self.claim,
            &self.evidence_set,
            &self.manifest,
            &self.source_revision,
            &self.lineage_root,
            &self.validity,
            &self.predecessors,
        ))
    }
    /// Returns the deterministic canonical JSON bytes of the identity shape.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ContractError> {
        crate::error::canonical_bytes(&(
            &self.proposition,
            &self.claim,
            &self.evidence_set,
            &self.manifest,
            &self.source_revision,
            &self.lineage_root,
            &self.validity,
            &self.predecessors,
        ))
    }
    /// Validates every identifier and the frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(
            self.proposition.as_str(),
            "identity.proposition",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(self.claim.as_str(), "identity.claim", MAX_SHORT_TEXT)?;
        validate_bounded_text(
            self.evidence_set.as_str(),
            "identity.evidence_set",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(self.manifest.as_str(), "identity.manifest", MAX_SHORT_TEXT)?;
        validate_bounded_text(
            self.source_revision.as_str(),
            "identity.source_revision",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(
            self.lineage_root.as_str(),
            "identity.lineage_root",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(self.validity.as_str(), "identity.validity", MAX_SHORT_TEXT)?;
        for predecessor in &self.predecessors {
            validate_bounded_text(
                predecessor.as_str(),
                "identity.predecessors",
                MAX_SHORT_TEXT,
            )?;
        }
        check_frozen(&self.digest, &self.compute_digest()?, "identity.digest")
    }
}

/// A derivation retaining its exact raw lineage: `derived_revision` must differ from `raw_source_revision`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransformedLineage {
    /// Lineage root of the raw input.
    pub raw_lineage_root: LineageRootId,
    /// Source revision of the raw input.
    pub raw_source_revision: SourceRevisionId,
    /// Bounded description of the transformation applied.
    pub transform: String,
    /// Source revision of the derived output.
    pub derived_revision: SourceRevisionId,
}
impl TransformedLineage {
    /// Constructs a transformation record retaining raw lineage.
    pub fn new(
        raw_lineage_root: LineageRootId,
        raw_source_revision: SourceRevisionId,
        transform: impl Into<String>,
        derived_revision: SourceRevisionId,
    ) -> Result<Self, ContractError> {
        let record = Self {
            raw_lineage_root,
            raw_source_revision,
            transform: transform.into(),
            derived_revision,
        };
        record.validate()?;
        Ok(record)
    }
    /// Validates raw lineage retention and the bounded transform description.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(
            self.raw_lineage_root.as_str(),
            "lineage.raw_lineage_root",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(
            self.raw_source_revision.as_str(),
            "lineage.raw_source_revision",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(&self.transform, "lineage.transform", MAX_SHORT_TEXT)?;
        validate_bounded_text(
            self.derived_revision.as_str(),
            "lineage.derived_revision",
            MAX_SHORT_TEXT,
        )?;
        if self.derived_revision == self.raw_source_revision {
            return Err(ContractError::ImpossibleCombination {
                field: "lineage.derived_revision",
            });
        }
        Ok(())
    }
}
