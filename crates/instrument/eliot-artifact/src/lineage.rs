//! Provenance lineage linking an artifact to its inputs and producer.

use crate::{ArtifactError, ArtifactIdentity, SourceBinding};
use eliot_contracts::{ClockReading, ContractId, OperationId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// How strongly a lineage link is bound to its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum LinkClass {
    /// The link is exact and receipt-backed.
    Exact,
    /// The link is bound through a durable receipt.
    ReceiptLinked,
    /// The link is correlated but not causally proven.
    Correlated,
    /// The link could not be disambiguated.
    Ambiguous,
    /// The link class cannot be established.
    Unknown,
}

/// The typed role a lineage link plays for the owning artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum LineageRole {
    /// A direct input to the artifact.
    Input,
    /// The artifact was derived from this target.
    DerivedFrom,
    /// This target produced the artifact.
    ProducedBy,
    /// This target verifies the artifact.
    VerifiedBy,
    /// The artifact supersedes this target.
    Supersedes,
    /// Another bounded role not in the stable set.
    Other,
}

/// One provenance link between the owning artifact and another identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LineageLink {
    /// The typed role this link plays.
    pub role: LineageRole,
    /// The linked artifact identity.
    pub target: ArtifactIdentity,
    /// Binding strength of the link.
    pub class: LinkClass,
}

impl LineageLink {
    /// Validates the target identity.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        self.target.validate()
    }
}

/// A provenance manifest for one immutable artifact.
///
/// The manifest records reconstructable traceability, not causal benefit: a
/// lineage link proves that an input relationship was recorded, not that the
/// relationship improved an outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LineageManifest {
    /// Upstream artifacts linked to the described artifact.
    pub parents: Vec<LineageLink>,
    /// Producing source, when known.
    pub producer: Option<SourceBinding>,
    /// Transform or normalizer contract, when one was applied.
    pub transform: Option<ContractId>,
    /// Effect-capable operation, when one produced the artifact.
    pub operation: Option<OperationId>,
    /// Creation clock.
    pub created_at: ClockReading,
}

impl LineageManifest {
    /// Validates links, producer and clock invariants.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        for link in &self.parents {
            link.validate()?;
        }
        if let Some(producer) = &self.producer {
            producer.validate()?;
        }
        self.created_at
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "created_at",
            })
    }
}
