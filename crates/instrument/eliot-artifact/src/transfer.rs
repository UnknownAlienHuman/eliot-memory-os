//! Verified import/export boundaries for canonical manifests.

use crate::{ArtifactError, ArtifactIdentity, ArtifactManifest, validate_digest};
use eliot_contracts::{ArtifactId, ClockReading};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The admitted export wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ExportFormat {
    /// Canonical JSON with recursively sorted object keys.
    CanonicalJsonV1,
}

/// A self-verifying export envelope carrying a canonical manifest.
///
/// The envelope stores an independent integrity digest over the full canonical
/// manifest bytes, so a transfer boundary can detect tampering with any field,
/// including the manifest identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactExport {
    /// Stable transfer identity.
    pub transfer_id: ArtifactId,
    /// Admitted wire format.
    pub format: ExportFormat,
    /// Lowercase SHA-256 digest of the full canonical manifest bytes.
    pub integrity: String,
    /// The carried manifest.
    pub manifest: ArtifactManifest,
    /// Export clock.
    pub exported_at: ClockReading,
}

impl ArtifactExport {
    /// Builds a verified export envelope for an already-validated manifest.
    pub fn build(
        transfer_id: ArtifactId,
        manifest: ArtifactManifest,
        exported_at: ClockReading,
    ) -> Result<Self, ArtifactError> {
        manifest.validate()?;
        let integrity = crate::sha256_hex(&crate::canonical_json_bytes(&manifest)?);
        let export = Self {
            transfer_id,
            format: ExportFormat::CanonicalJsonV1,
            integrity,
            manifest,
            exported_at,
        };
        export.validate()?;
        Ok(export)
    }

    /// Validates format, integrity digest, manifest and clock invariants.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.format != ExportFormat::CanonicalJsonV1 {
            return Err(ArtifactError::Unsupported {
                field: "format",
                reason: "only canonical JSON v1 is admitted",
            });
        }
        validate_digest(&self.integrity, "integrity")?;
        self.manifest.validate()?;
        self.exported_at
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "exported_at",
            })
    }
}

/// A durable receipt proving a transfer boundary was verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TransferReceipt {
    /// Stable transfer identity.
    transfer_id: ArtifactId,
    /// The verified manifest identity.
    manifest_identity: ArtifactIdentity,
    /// Integrity digest that was recomputed and matched.
    integrity: String,
    /// Verification clock.
    verified_at: ClockReading,
}

impl TransferReceipt {
    /// Returns the owner-issued transfer identity.
    #[must_use]
    pub fn transfer_id(&self) -> &ArtifactId {
        &self.transfer_id
    }

    /// Returns the verified manifest identity.
    #[must_use]
    pub fn manifest_identity(&self) -> &ArtifactIdentity {
        &self.manifest_identity
    }

    /// Returns the recomputed envelope digest.
    #[must_use]
    pub fn integrity(&self) -> &str {
        &self.integrity
    }

    /// Returns the import verification clock.
    #[must_use]
    pub const fn verified_at(&self) -> &ClockReading {
        &self.verified_at
    }
}

/// The typed result of verifying an import at a transfer boundary.
///
/// Fields stay private and the type is not deserializable: an imported
/// artifact is an owner-issued accepted value, not a caller-assertable wire
/// claim. Use the accessors to inspect the verified manifest and receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedArtifact {
    /// The verified manifest.
    manifest: ArtifactManifest,
    /// The transfer receipt.
    receipt: TransferReceipt,
}

impl ImportedArtifact {
    /// Returns the manifest accepted by the import verifier.
    #[must_use]
    pub fn manifest(&self) -> &ArtifactManifest {
        &self.manifest
    }

    /// Returns the owner-issued transfer receipt.
    #[must_use]
    pub fn receipt(&self) -> &TransferReceipt {
        &self.receipt
    }
}

/// Verifies an export at an import boundary.
///
/// The import recomputes the integrity digest over the full canonical manifest
/// bytes and re-validates the manifest identity, schema and source bindings. A
/// mismatch yields a typed [`ArtifactError::Corrupted`] or
/// [`ArtifactError::DigestMismatch`], never a silently accepted import.
pub fn verify_import(
    export: ArtifactExport,
    verified_at: ClockReading,
) -> Result<ImportedArtifact, ArtifactError> {
    export.validate()?;
    verified_at
        .validate()
        .map_err(|_| ArtifactError::InvalidInterval {
            field: "verified_at",
        })?;

    let computed = crate::sha256_hex(&crate::canonical_json_bytes(&export.manifest)?);
    if computed != export.integrity {
        return Err(ArtifactError::DigestMismatch {
            field: "export.integrity",
            expected: export.integrity,
            actual: computed,
        });
    }

    let receipt = TransferReceipt {
        transfer_id: export.transfer_id,
        manifest_identity: export.manifest.identity.clone(),
        integrity: computed,
        verified_at,
    };
    Ok(ImportedArtifact {
        manifest: export.manifest,
        receipt,
    })
}
