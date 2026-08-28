//! Passive package-staging observation and receipt data models.
//!
//! This child owns only passive source/staging observation and receipt DTOs
//! plus their local representation. The parent staging adapter owns
//! authorization, filesystem/Windows effects, validation, reconciliation, and
//! installation authority; this child owns no lifecycle or mutable state.
//!
//! Architecture A5.1 (Reality and observation): ELIOT stores bounded
//! observations and models rather than external reality.
//! Implementation I3.15 (Installation and update transaction): immutable
//! installation plan and staging/artifact evidence support installer/Host
//! execution and recovery, which remain outside this child.
//! Implementation I2.1 (Rust workspace, crate fleet, ownership and hot path):
//! module/crate membership changes physical packaging only and transfers no
//! lifecycle, mutable-state, or authority ownership.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{AuthenticodeEvidence, FileIdentity, PackageStagingError, PeCoffEvidence, hex_digest};

/// One independently measured regular source file.
///
/// This is intentionally narrower than [`StagedFileReceipt`]: it contains no
/// destination, security, PE, Authenticode, manifest or approval fields.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSourceFileObservation {
    /// Canonical slash-separated path below the retained source root.
    pub relative_path: String,
    /// Lowercase SHA-256 of the bytes read from the retained file handle.
    pub sha256: String,
    /// Windows volume/file-object identity observed from the same handle.
    pub identity: FileIdentity,
    /// Number of bytes read from the same handle.
    pub size: u64,
    /// PE/COFF evidence parsed from the same handle-bound prefix when the
    /// object is an AMD64 PE32+ executable.
    pub pe: Option<PeCoffEvidence>,
}

/// Complete bounded read-only observation of a trusted source bundle.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSourceObservation {
    /// File facts sorted by Windows ordinal whole-component path order.
    pub files: Vec<PackageSourceFileObservation>,
    /// Aggregate bytes read from all observed files.
    pub total_bytes: u64,
}

/// Receipt for one copied package file.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedFileReceipt {
    /// Canonical package-relative path.
    pub relative_path: String,
    /// Source file identity observed before copying.
    pub source_identity: FileIdentity,
    /// Destination file identity observed after copying.
    pub destination_identity: FileIdentity,
    /// Source/destination byte size.
    pub size: u64,
    /// Source/destination SHA-256 digest.
    pub sha256: String,
    /// SHA-256 digest of the final protected security descriptor.
    pub security_descriptor_sha256: String,
    /// PE/COFF evidence for executable entries.
    pub pe: Option<PeCoffEvidence>,
    /// Authenticode evidence for executable entries.
    pub authenticode: Option<AuthenticodeEvidence>,
}

/// Receipt for one create-only directory below the generation root.
///
/// Directory identities are retained so rollback can prove ownership before
/// deleting nested directories; the root directory has its own identity field
/// on [`StagingReceipt`].
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedDirectoryReceipt {
    /// Canonical package-relative directory path.
    pub relative_path: String,
    /// Directory identity observed after creation.
    pub identity: FileIdentity,
    /// SHA-256 digest of the final protected security descriptor.
    pub security_descriptor_sha256: String,
}

/// Complete immutable package staging receipt.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagingReceipt {
    /// Manifest generation identity.
    pub generation: String,
    /// Canonical absolute generation-root path.
    pub root_path: PathBuf,
    /// Root directory identity captured after creation.
    pub root_identity: FileIdentity,
    /// Exact nested directories created below the generation root.
    pub directories: Vec<StagedDirectoryReceipt>,
    /// Exact file receipts sorted by ordinal path.
    pub files: Vec<StagedFileReceipt>,
    /// Canonical manifest SHA-256 digest.
    pub manifest_sha256: String,
}

impl StagingReceipt {
    /// Return a stable digest of the receipt itself for an outer coordinator.
    #[must_use]
    pub fn digest(&self) -> String {
        serde_json::to_vec(self).map_or_else(
            |_| hex_digest(b"staging-receipt-serialization-failed"),
            |bytes| hex_digest(&bytes),
        )
    }
}

/// Explicit result of inspecting a generation tree.
///
/// There is intentionally no `Staged` variant.  A complete receipt is either
/// returned as `Matching` or the tree is classified as absent, mismatched or
/// unknown; a crash/partial tree can never be promoted by this primitive.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PackageStagingObservation {
    /// Generation root is absent while its retained parent contour is stable.
    Absent,
    /// Existing tree exactly matches the supplied receipt.
    Matching(StagingReceipt),
    /// Existing tree is present but differs from the receipt/manifest.
    Mismatch(PackageStagingError),
    /// The OS could not classify the tree safely.
    Unknown(PackageStagingError),
}
