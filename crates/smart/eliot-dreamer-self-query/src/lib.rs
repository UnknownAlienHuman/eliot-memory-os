//! Bounded Dreamer self-query over refs by handle (#223).
//!
//! [`SelfQueryRequest`] binds one question and one task family to one scope
//! and one [`StateFence`], with the already-compiled
//! `ActiveUnderstandingView` handle and the accepted-source and evidence
//! handles it may cite. [`pose`] validates the request and freezes a
//! canonical request digest into a [`SelfQueryCandidate`] for downstream
//! brief handlers.
//!
//! The package never compiles context, never admits, never authors
//! `ArchitectureBrief` or `ImplementationBrief` output, and never calls a
//! model route. The accepted-source projection stays `NOT_FROZEN` in
//! `crates/smart/cognitive-rev12-contract-schema-freeze.toml` (CC-006):
//! source refs travel as handles only.

#![forbid(unsafe_code)]

use eliot_contracts::{ArtifactId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";

/// Hard ceiling on source/evidence refs carried by one request.
pub const MAX_SELF_QUERY_REFS: usize = 32;
/// Maximum bytes accepted for one subject text field.
pub const MAX_SUBJECT_TEXT: usize = 1024;
/// Maximum Unicode scalar values accepted for one scope identity.
pub const MAX_SCOPE_CHARS: usize = 256;

/// Self-query failure: every case fails closed with its reason.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SelfQueryError {
    /// A subject, scope, or fence shape is invalid.
    #[error("dreamer self query: invalid field {field}: {reason}")]
    InvalidField {
        /// Field at fault.
        field: &'static str,
        /// Why it is invalid.
        reason: &'static str,
    },
    /// A bound on refs, text, or scope is exceeded.
    #[error("dreamer self query: out of bounds: {field}")]
    Bounds {
        /// Field at fault.
        field: &'static str,
    },
    /// The request could not be canonically encoded for digesting.
    #[error("dreamer self query: request is not digestible")]
    NotDigestible,
}

fn text(value: &str, field: &'static str) -> Result<(), SelfQueryError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SelfQueryError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    if value.len() > MAX_SUBJECT_TEXT {
        return Err(SelfQueryError::Bounds { field });
    }
    Ok(())
}

/// The question under query: one question in one task family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfQuerySubject {
    /// The exact question, non-blank, at most 1024 bytes.
    pub question: String,
    /// The task family the question belongs to, non-blank.
    pub task_family: String,
}

impl SelfQuerySubject {
    /// Validate subject shape.
    pub fn validate(&self) -> Result<(), SelfQueryError> {
        text(&self.question, "subject.question")?;
        text(&self.task_family, "subject.task_family")
    }
}

/// One validated fence-bound self-query request.
///
/// All evidence travels as handles: `view_ref` names the already-compiled
/// view, `source_refs` name accepted-source and outcome/verifier evidence.
/// Nothing here compiles, admits, or briefs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfQueryRequest {
    /// The question under query.
    pub subject: SelfQuerySubject,
    /// Exact work scope the query runs under.
    pub scope_id: WorkScopeId,
    /// Fence every cited handle must satisfy downstream.
    pub state_fence: StateFence,
    /// Handle of the already-compiled view to read.
    pub view_ref: ArtifactId,
    /// Accepted-source and evidence handles the query may cite.
    pub source_refs: Vec<ArtifactId>,
}

impl SelfQueryRequest {
    /// Construct a validated request.
    pub fn new(
        subject: SelfQuerySubject,
        scope_id: WorkScopeId,
        state_fence: StateFence,
        view_ref: ArtifactId,
        source_refs: Vec<ArtifactId>,
    ) -> Result<Self, SelfQueryError> {
        let request = Self {
            subject,
            scope_id,
            state_fence,
            view_ref,
            source_refs,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validate subject, scope, fence, view ref, and ref bounds.
    pub fn validate(&self) -> Result<(), SelfQueryError> {
        self.subject.validate()?;
        if self.scope_id.as_str().chars().count() > MAX_SCOPE_CHARS {
            return Err(SelfQueryError::Bounds {
                field: "request.scope_id",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| SelfQueryError::InvalidField {
                field: "request.state_fence",
                reason: "fence interval is invalid",
            })?;
        text(self.view_ref.as_str(), "request.view_ref")?;
        if self.source_refs.len() > MAX_SELF_QUERY_REFS {
            return Err(SelfQueryError::Bounds {
                field: "request.source_refs",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for handle in &self.source_refs {
            text(handle.as_str(), "request.source_refs")?;
            if !seen.insert(handle.as_str().to_owned()) {
                return Err(SelfQueryError::InvalidField {
                    field: "request.source_refs",
                    reason: "duplicate handle",
                });
            }
        }
        Ok(())
    }
}

/// A posed self-query: the validated request plus its frozen digest.
///
/// The digest is sha256 over the canonical JSON bytes of the request. It
/// identifies the posed query for downstream brief handlers; it proves
/// nothing about understanding, support, or truth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfQueryCandidate {
    /// The validated request.
    pub request: SelfQueryRequest,
    /// Canonical digest frozen at pose time.
    pub request_digest: String,
}

impl SelfQueryCandidate {
    /// Validate the candidate: request shape plus digest recomputation.
    pub fn validate(&self) -> Result<(), SelfQueryError> {
        self.request.validate()?;
        let bytes =
            canonical_json_bytes(&self.request).map_err(|_| SelfQueryError::NotDigestible)?;
        if sha256_hex(&bytes) != self.request_digest {
            return Err(SelfQueryError::InvalidField {
                field: "candidate.request_digest",
                reason: "digest does not match the request",
            });
        }
        Ok(())
    }
}

/// Pose a self-query: validate the request and freeze its digest.
pub fn pose(request: &SelfQueryRequest) -> Result<SelfQueryCandidate, SelfQueryError> {
    request.validate()?;
    let bytes = canonical_json_bytes(request).map_err(|_| SelfQueryError::NotDigestible)?;
    Ok(SelfQueryCandidate {
        request: request.clone(),
        request_digest: sha256_hex(&bytes),
    })
}
