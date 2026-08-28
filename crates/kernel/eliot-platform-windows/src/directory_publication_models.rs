//! Architecture A5.1 (bounded observations/models; reality external).
//! Implementation I3.15 (installation/update transaction: installer/Host owns
//! filesystem publication and durable recovery).
//! Implementation I2.1 (module/crate membership transfers no lifecycle,
//! mutable-state, or authority ownership).
//!
//! Ownership: child owns only passive directory-publication error/receipt/outcome
//! DTOs plus local validation/accessors; parent adapter owns filesystem handles,
//! security, rename/publication/recovery effects; installer/Host control plane
//! owns installation and canonical authority.

use crate::FileIdentity;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Failure before a create-new directory publication can commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryPublicationError {
    /// A caller path is relative, traversing, non-canonical or not an owned
    /// same-parent temporary name.
    InvalidPath,
    /// An ancestor, parent or source directory is a reparse point.
    ReparsePoint,
    /// The destination already exists, including a concurrent create race.
    AlreadyExists,
    /// A retained source, parent or destination object changed identity.
    IdentityMismatch,
    /// Windows failed before the move committed.
    Io,
    /// A documented Win32 call failed before the move committed.
    Win32 { code: u32 },
    /// The primitive is intentionally unavailable off Windows.
    UnsupportedPlatform,
}

impl std::fmt::Display for DirectoryPublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "directory publication path is invalid",
            Self::ReparsePoint => "directory publication contour contains a reparse point",
            Self::AlreadyExists => "directory publication destination already exists",
            Self::IdentityMismatch => "directory publication identity changed",
            Self::Io => "directory publication I/O failed before commit",
            Self::Win32 { .. } => "directory publication Win32 call failed before commit",
            Self::UnsupportedPlatform => "directory publication requires Windows",
        })
    }
}

impl std::error::Error for DirectoryPublicationError {}

/// Exact identity receipt after a create-new directory move is read back.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPublicationReceipt {
    /// Caller-declared final path, validated against retained handles.
    pub destination_path: String,
    /// Canonical retained parent path used by the move.
    pub canonical_parent_path: String,
    /// Identity of the retained destination parent.
    pub parent_identity: FileIdentity,
    /// Identity of the owned temporary directory before the move.
    pub source_identity: FileIdentity,
    /// Identity of the destination directory after the move.
    pub destination_identity: FileIdentity,
}

/// Why a committed directory move could not be promoted to a receipt.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectoryPublicationUnknown {
    /// Test or provider discrimination made the post-commit read unavailable.
    PostCommitReadbackUnavailable,
    /// The retained moved handle no longer named the expected destination.
    PostCommitPathChanged,
    /// The moved or reopened destination identity could not be measured.
    PostCommitIdentityUnavailable,
    /// The moved or reopened destination was not the exact source object.
    PostCommitIdentityChanged,
}

/// Durable facts retained when the move committed but readback is uncertain.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPublicationUnknownReceipt {
    /// Exact reason receipt promotion was withheld.
    pub reason: DirectoryPublicationUnknown,
    /// Caller-declared final path of the committed move.
    pub destination_path: String,
    /// Canonical retained parent path used by the move.
    pub canonical_parent_path: String,
    /// Identity of the retained destination parent.
    pub parent_identity: FileIdentity,
    /// Exact identity of the owned temporary directory passed to the move.
    pub source_identity: FileIdentity,
}

/// Create-new directory publication result. A successful OS move never
/// becomes `Err`: post-commit ambiguity is returned with reconcilable facts.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum DirectoryPublicationOutcome {
    /// Destination path and directory identity were read back exactly.
    Published(DirectoryPublicationReceipt),
    /// The move committed, but receipt promotion requires reconciliation.
    CommittedUnknown(DirectoryPublicationUnknownReceipt),
}
