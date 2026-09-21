//! Governed source-readback contracts for retrieval-to-projection citation.
//!
//! Index and vector payloads are non-authoritative previews only. A citation
//! requires reopening the exact admitted source revision under the same
//! source view, workspace-view revision and state fence, verifying digest
//! and byte length, resolving the anchor through exact coordinates or native
//! mapping, and verifying the excerpt digest. This module owns schemas and
//! intrinsic validation only; it performs no I/O, reopening or persistence.

use eliot_contracts::StateFence;
use eliot_observation_contracts::{
    SourceAnchorHandle, SourceRevisionHandle, SourceViewHandle, WorkspaceViewRevisionHandle,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextError, validate_digest, validate_text};

/// Maximum index-preview bytes retained for non-authoritative display.
pub const MAX_PREVIEW_BYTES: usize = 1_048_576;
/// Maximum citable excerpt bytes returned by the readback gate.
pub const MAX_EXCERPT_BYTES: usize = 1_048_576;

/// Authority marking for an index or vector payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreviewAuthority {
    /// The payload is a non-authoritative preview and can never be cited.
    NonAuthoritativePreview,
}

/// Non-authoritative index or vector payload text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IndexPreview {
    /// Preview bytes; never cited as support.
    pub bytes: Vec<u8>,
    /// Revision the preview claims to describe, for mismatch detection.
    pub claimed_revision: String,
    /// Must always be the non-authoritative preview marker.
    pub authority: PreviewAuthority,
}

impl IndexPreview {
    /// Validate preview shape; authority is always non-authoritative.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.bytes.len() > MAX_PREVIEW_BYTES {
            return Err(ContextError::Bounds {
                field: "readback.preview.bytes",
            });
        }
        validate_text(&self.claimed_revision, "readback.preview.claimed_revision")?;
        if self.authority != PreviewAuthority::NonAuthoritativePreview {
            return Err(ContextError::InvalidField("readback.preview.authority"));
        }
        Ok(())
    }

    /// Whether this payload may be cited as support. Always false.
    #[must_use]
    pub const fn is_citable(&self) -> bool {
        false
    }
}

/// Typed readback refusal when revision, mapping, length or digest fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadbackRefusalKind {
    /// Citation is not supported for this revision, mapping or digest.
    Unsupported,
    /// Workspace-view or fence drift requires a fresh plan before retry.
    Replan,
    /// Verified bytes are missing; the caller holds a typed gap.
    Gap,
}

/// Exact refusal returned instead of a citation to convenient bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadbackRefusal {
    /// Machine-readable refusal class; consumers must branch on this value.
    pub kind: ReadbackRefusalKind,
    /// Stable reason identity; never carries payload bytes.
    pub reason: String,
    /// Missing handle identity when the refusal names a gap.
    pub missing_handle: Option<String>,
}

impl ReadbackRefusal {
    /// Construct an unsupported-result refusal.
    pub fn unsupported(reason: &'static str) -> Self {
        Self {
            kind: ReadbackRefusalKind::Unsupported,
            reason: reason.to_owned(),
            missing_handle: None,
        }
    }

    /// Construct a replan refusal for view or fence drift.
    pub fn replan(reason: &'static str) -> Self {
        Self {
            kind: ReadbackRefusalKind::Replan,
            reason: reason.to_owned(),
            missing_handle: None,
        }
    }

    /// Construct a typed gap for missing digest, length or excerpt bytes.
    pub fn gap(reason: &'static str, missing_handle: Option<String>) -> Self {
        Self {
            kind: ReadbackRefusalKind::Gap,
            reason: reason.to_owned(),
            missing_handle,
        }
    }

    /// Validate the refusal shape.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(&self.reason, "readback.refusal.reason")?;
        if let Some(handle) = &self.missing_handle {
            validate_text(handle, "readback.refusal.missing_handle")?;
        }
        Ok(())
    }
}

/// Request to cite projected material after governed readback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadbackRequest {
    /// Exact admitted source revision that must be reopened.
    pub admitted: SourceRevisionHandle,
    /// Active source view the reopen must use.
    pub view: SourceViewHandle,
    /// Workspace-view revision shared by the compound query.
    pub workspace_revision: WorkspaceViewRevisionHandle,
    /// State fence the reopened bytes must satisfy.
    pub fence: StateFence,
    /// Requested anchor with excerpt digest.
    pub anchor: SourceAnchorHandle,
    /// Non-authoritative preview; never cited.
    pub preview: IndexPreview,
}

impl ReadbackRequest {
    /// Validate every handle shape without opening source bytes.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.admitted
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.admitted"))?;
        self.view
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.view"))?;
        self.workspace_revision
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.workspace_revision"))?;
        self.fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        self.anchor
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.anchor"))?;
        self.preview.validate()
    }
}

/// Projected citation backed by verified readback bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectedCitation {
    /// Exact admitted source revision that was reopened and verified.
    pub source_revision: SourceRevisionHandle,
    /// Exact anchor handle used for readback.
    pub anchor: SourceAnchorHandle,
    /// Source view used for the reopen.
    pub view: SourceViewHandle,
    /// Workspace-view revision used for the reopen.
    pub workspace_revision: WorkspaceViewRevisionHandle,
    /// State fence the reopened bytes satisfy.
    pub fence: StateFence,
    /// Verified excerpt bytes sliced from the reopened revision.
    pub excerpt_bytes: Vec<u8>,
    /// Digest of `excerpt_bytes`, matching the anchor excerpt digest.
    pub excerpt_digest: String,
}

impl ProjectedCitation {
    /// Validate handle shapes and excerpt digest binding.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.source_revision
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.citation.source_revision"))?;
        self.anchor
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.citation.anchor"))?;
        self.view
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.citation.view"))?;
        self.workspace_revision
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.citation.workspace_revision"))?;
        self.fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        if self.excerpt_bytes.is_empty() || self.excerpt_bytes.len() > MAX_EXCERPT_BYTES {
            return Err(ContextError::Bounds {
                field: "readback.citation.excerpt_bytes",
            });
        }
        validate_digest(&self.excerpt_digest, "readback.citation.excerpt_digest")?;
        let expected = eliot_contracts::sha256_hex(&self.excerpt_bytes);
        if expected != self.excerpt_digest || expected != self.anchor.excerpt_sha256 {
            return Err(ContextError::IdentityConflict);
        }
        let length = u64::try_from(self.excerpt_bytes.len()).map_err(|_| ContextError::Overflow)?;
        if length != self.anchor.byte_length {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}
