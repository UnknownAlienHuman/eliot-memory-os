use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContractError, Digest, text};

/// Wire revision of the inert descriptor itself.
pub const LEGACY_DESCRIPTOR_VERSION: &str = "v1";

/// Explicitly versioned, inert migration descriptor for retired curation DTOs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacyMigrationDescriptor {
    /// Explicit descriptor wire revision.
    pub descriptor_version: String,
    /// Retired source wire version.
    pub source_version: String,
    /// Fields intentionally lost by the migration.
    pub lost_fields: Vec<String>,
    /// Current target owner name.
    pub target_owner: String,
    /// Issue that owns a future decoder/migration.
    pub migration_issue: u64,
    /// Digest of the descriptor itself.
    pub descriptor_digest: Digest,
}
impl LegacyMigrationDescriptor {
    /// Validates metadata without decoding or applying the legacy wire.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.descriptor_version != LEGACY_DESCRIPTOR_VERSION {
            return Err(ContractError::Unsupported {
                field: "legacy.descriptor_version",
            });
        }
        text(&self.source_version, "legacy.source_version")?;
        text(&self.target_owner, "legacy.target_owner")?;
        if self.migration_issue == 0 {
            return Err(ContractError::Zero {
                field: "legacy.migration_issue",
            });
        }
        if self
            .lost_fields
            .iter()
            .any(|field| text(field, "legacy.lost_fields").is_err())
        {
            return Err(ContractError::Blank {
                field: "legacy.lost_fields",
            });
        }
        Ok(())
    }
}
