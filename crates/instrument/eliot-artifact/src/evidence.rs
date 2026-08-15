//! Raw evidence handles and reversible omission references.

use crate::{ArtifactError, ArtifactIdentity, ArtifactKind, validate_digest, validate_text};
use eliot_contracts::{ArtifactId, ClockReading, ContractId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A bounded, inclusive byte range of omitted material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ByteRange {
    /// Inclusive start offset.
    pub start: u64,
    /// Exclusive end offset.
    pub end_exclusive: u64,
}

impl ByteRange {
    /// Validates that the range is non-empty and ordered.
    pub fn validate(self) -> Result<(), ArtifactError> {
        if self.end_exclusive <= self.start {
            return Err(ArtifactError::InvalidInterval { field: "range" });
        }
        Ok(())
    }
}

/// Completeness of a shortened payload relative to its retained source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum Completeness {
    /// The exact source is fully preserved behind a reversible handle.
    Complete,
    /// Only part of the source is preserved.
    Partial,
    /// The retained source is no longer available.
    SourceUnavailable,
    /// Completeness cannot be established.
    Unknown,
}

/// A typed reason for shortening a payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum OmissionReason {
    /// A bounded payload budget required shortening.
    Budget,
    /// Privacy or redaction policy removed material.
    Privacy,
    /// The renderer selected a bounded preview.
    Preview,
    /// The source was captured truncated upstream.
    TruncatedCapture,
    /// Another governed reducer was applied.
    Reducer,
    /// No typed reason is known.
    Unknown,
}

/// A durable, reversible reference to material that was shortened.
///
/// Silent truncation is forbidden: every shortened payload must carry either a
/// complete reference back to a retained source or an explicit `SourceUnavailable`
/// completeness state that cannot be laundered as absence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OmissionReference {
    /// Stable identity of this omission.
    pub omission_id: ArtifactId,
    /// Content-addressed reference to the retained source bytes, when present.
    pub source: Option<crate::ContentAddress>,
    /// Lowercase SHA-256 digest of the retained source checksum.
    pub source_checksum: String,
    /// Original byte count before shortening.
    pub original_bytes: u64,
    /// Rendered byte count after shortening.
    pub rendered_bytes: u64,
    /// Exact omitted ranges, when they are known.
    pub omitted_ranges: Vec<ByteRange>,
    /// Typed shortening reason.
    pub reason: OmissionReason,
    /// Completeness of the retained source.
    pub completeness: Completeness,
    /// Renderer or reducer contract, when one was applied.
    pub renderer: Option<ContractId>,
    /// Creation clock.
    pub created_at: ClockReading,
}

impl OmissionReference {
    /// Validates identity, checksum, byte accounting, ranges and completeness.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        validate_digest(&self.source_checksum, "source_checksum")?;
        if self.rendered_bytes > self.original_bytes {
            return Err(ArtifactError::InvalidInterval {
                field: "rendered_bytes",
            });
        }
        for range in &self.omitted_ranges {
            range.validate()?;
        }
        if self.completeness == Completeness::Complete && self.source.is_none() {
            return Err(ArtifactError::TruncatedWithoutOmission {
                field: "omission.source",
            });
        }
        self.created_at
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "created_at",
            })
    }
}

/// A location-independent reference to an immutable raw evidence payload.
///
/// The handle carries content addressing and truncation metadata only; it never
/// carries inline bytes. The durable blob storage behind the address is owned by
/// the blob-store boundary, not by this contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawEvidenceHandle {
    /// Content-addressed identity of the raw payload.
    pub identity: ArtifactIdentity,
    /// MIME-like type, such as `text/plain` or `application/json`.
    pub content_type: String,
    /// Whether the capture ended at an explicit truncation boundary.
    pub truncated: bool,
    /// Reversible omission reference when the payload was shortened.
    pub truncation: Option<OmissionReference>,
    /// Capture clock.
    pub captured_at: ClockReading,
}

impl RawEvidenceHandle {
    /// Validates identity, content type, truncation and clock invariants.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.identity.kind != ArtifactKind::RawEvidence {
            return Err(ArtifactError::Unsupported {
                field: "identity.kind",
                reason: "raw evidence handle requires raw evidence identity",
            });
        }
        self.identity.validate()?;
        validate_text(&self.content_type, "content_type")?;
        if self.truncated && self.truncation.is_none() {
            return Err(ArtifactError::TruncatedWithoutOmission {
                field: "truncation",
            });
        }
        if !self.truncated && self.truncation.is_some() {
            return Err(ArtifactError::InvalidInterval {
                field: "truncation",
            });
        }
        if let Some(truncation) = &self.truncation {
            truncation.validate()?;
        }
        self.captured_at
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "captured_at",
            })
    }
}
