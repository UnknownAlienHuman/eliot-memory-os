//! Source and schema bindings for immutable artifacts.

use crate::{ArtifactError, validate_digest, validate_text};
use eliot_contracts::{ContractId, ContractVersion, SourceId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A schema binding that pins an artifact to its admitted shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SchemaBinding {
    /// Stable schema contract identity.
    pub schema_id: ContractId,
    /// Semantic wire revision of the schema.
    pub version: ContractVersion,
    /// Lowercase SHA-256 digest of the canonical schema shape.
    pub shape_sha256: String,
}

impl SchemaBinding {
    /// Validates the schema identity and shape digest.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        validate_digest(&self.shape_sha256, "shape_sha256")
    }
}

/// A source binding that pins an artifact to its producing origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceBinding {
    /// Stable identity of the producing source.
    pub source_id: SourceId,
    /// Exact source revision, commit or worktree identity.
    pub revision: String,
    /// Optional content digest of the source snapshot, when captured.
    pub integrity: Option<String>,
}

impl SourceBinding {
    /// Validates the source identity, revision and integrity digest.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        validate_text(&self.revision, "revision")?;
        if let Some(integrity) = &self.integrity {
            validate_digest(integrity, "integrity")?;
        }
        Ok(())
    }
}
