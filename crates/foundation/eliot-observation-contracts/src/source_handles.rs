//! Governed source-readback handle types.
//!
//! Handles only: identity, revision, view and anchor references used to bind
//! a citation to the exact admitted source revision. This module performs no
//! I/O, retrieval, ranking, reopening, verification or persistence.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ObservationError;

fn text(value: &str, field: &'static str) -> Result<(), ObservationError> {
    if value.trim().is_empty() {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn bounded_text(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ObservationError> {
    text(value, field)?;
    if value.chars().count() > max_chars {
        return Err(ObservationError::InvalidField {
            field,
            reason: "exceeds bounded length",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ObservationError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

/// What "current" means for one governed readback operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceViewKind {
    WorkingTreeCurrent,
    GitIndex,
    GitCommit,
    ImportedSnapshot,
    RetainedRevision,
}

/// Explicit source view selected before planning or readback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceViewHandle {
    /// Which surface the readback must reopen.
    pub kind: SourceViewKind,
    /// Workspace instance the view belongs to.
    pub workspace_instance_id: String,
    /// Workspace-view revision shared by one compound query.
    pub workspace_view_revision: String,
    /// Required only for `GitCommit`.
    pub git_commit_oid: Option<String>,
    /// Required only for `ImportedSnapshot`.
    pub imported_snapshot_id: Option<String>,
    /// Required only for `RetainedRevision`.
    pub retained_revision_id: Option<String>,
}

impl SourceViewHandle {
    /// Validate shape and kind-specific handle presence without opening bytes.
    pub fn validate(&self) -> Result<(), ObservationError> {
        bounded_text(
            &self.workspace_instance_id,
            "source_view.workspace_instance_id",
            256,
        )?;
        bounded_text(
            &self.workspace_view_revision,
            "source_view.workspace_view_revision",
            256,
        )?;
        for (value, field) in [
            (&self.git_commit_oid, "source_view.git_commit_oid"),
            (
                &self.imported_snapshot_id,
                "source_view.imported_snapshot_id",
            ),
            (
                &self.retained_revision_id,
                "source_view.retained_revision_id",
            ),
        ] {
            if let Some(value) = value {
                bounded_text(value, field, 256)?;
            }
        }
        match self.kind {
            SourceViewKind::GitCommit => {
                if self.git_commit_oid.is_none()
                    || self.imported_snapshot_id.is_some()
                    || self.retained_revision_id.is_some()
                {
                    return Err(ObservationError::InvalidField {
                        field: "source_view.git_commit_oid",
                        reason: "git_commit view requires only git_commit_oid",
                    });
                }
            }
            SourceViewKind::ImportedSnapshot => {
                if self.imported_snapshot_id.is_none()
                    || self.git_commit_oid.is_some()
                    || self.retained_revision_id.is_some()
                {
                    return Err(ObservationError::InvalidField {
                        field: "source_view.imported_snapshot_id",
                        reason: "imported_snapshot view requires only imported_snapshot_id",
                    });
                }
            }
            SourceViewKind::RetainedRevision => {
                if self.retained_revision_id.is_none()
                    || self.git_commit_oid.is_some()
                    || self.imported_snapshot_id.is_some()
                {
                    return Err(ObservationError::InvalidField {
                        field: "source_view.retained_revision_id",
                        reason: "retained_revision view requires only retained_revision_id",
                    });
                }
            }
            SourceViewKind::WorkingTreeCurrent | SourceViewKind::GitIndex => {
                if self.git_commit_oid.is_some()
                    || self.imported_snapshot_id.is_some()
                    || self.retained_revision_id.is_some()
                {
                    return Err(ObservationError::InvalidField {
                        field: "source_view.revision_ref",
                        reason: "working_tree_current and git_index carry no commit handle",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Operation-local workspace-view revision shared by one compound query.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceViewRevisionHandle {
    /// Workspace instance this revision was observed on.
    pub workspace_instance_id: String,
    /// Opaque inventory revision for the observed view.
    pub view_revision: String,
}

impl WorkspaceViewRevisionHandle {
    /// Validate the workspace revision binding without opening bytes.
    pub fn validate(&self) -> Result<(), ObservationError> {
        bounded_text(
            &self.workspace_instance_id,
            "workspace_revision.workspace_instance_id",
            256,
        )?;
        bounded_text(&self.view_revision, "workspace_revision.view_revision", 256)
    }
}

/// Exact admitted source revision a citation must be read back from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceRevisionHandle {
    /// Stable source identity within the governed owner.
    pub source_id: String,
    /// Immutable revision within that source.
    pub revision: String,
    /// Digest of the complete admitted source bytes.
    pub content_sha256: String,
    /// Length of the complete admitted source bytes.
    pub byte_length: u64,
}

impl SourceRevisionHandle {
    /// Validate revision identity and digest shape without opening bytes.
    pub fn validate(&self) -> Result<(), ObservationError> {
        bounded_text(&self.source_id, "source_revision.source_id", 256)?;
        bounded_text(&self.revision, "source_revision.revision", 256)?;
        digest(&self.content_sha256, "source_revision.content_sha256")
    }
}

/// Exact anchor resolved through stored coordinates or native mapping.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAnchorHandle {
    /// Stable anchor identity within the admitted revision.
    pub anchor_id: String,
    /// Byte offset of the excerpt in the admitted source bytes.
    pub byte_offset: u64,
    /// Byte length of the excerpt; must be non-empty to be citable.
    pub byte_length: u64,
    /// Digest of the exact excerpt bytes.
    pub excerpt_sha256: String,
    /// Native coordinate mapping when the owner does not use raw offsets.
    pub native_mapping: Option<String>,
}

impl SourceAnchorHandle {
    /// Validate anchor coordinates and excerpt digest shape.
    pub fn validate(&self) -> Result<(), ObservationError> {
        bounded_text(&self.anchor_id, "source_anchor.anchor_id", 256)?;
        if self.byte_length == 0 {
            return Err(ObservationError::InvalidField {
                field: "source_anchor.byte_length",
                reason: "excerpt must be non-empty",
            });
        }
        digest(&self.excerpt_sha256, "source_anchor.excerpt_sha256")?;
        if let Some(mapping) = &self.native_mapping {
            bounded_text(mapping, "source_anchor.native_mapping", 1024)?;
        }
        Ok(())
    }
}
