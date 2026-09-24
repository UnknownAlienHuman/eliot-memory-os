//! Current Epistemic Position algebra: the resolver-owned position types.
//!
//! `PositionState`, `EpistemicRecord`, `PositionRequest`, `ProvenanceView`
//! and the local [`CurrentEpistemicPosition`] plus the shared
//! [`EpistemicError`] validation vocabulary. Wire types stay with
//! `eliot-epistemic-contracts`; this algebra is resolver policy over
//! admitted, fenced evidence, never a wire duplicate.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence};
use eliot_evidence::{Assertability, EvidenceEnvelope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum EpistemicError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("epistemic input has no records")]
    EmptyInput,
    #[error("epistemic input contains duplicate handle {0}")]
    DuplicateHandle(ArtifactId),
    #[error("record {handle} supersedes itself")]
    SelfSupersession { handle: ArtifactId },
    #[error("record {handle} contains duplicate predecessor {predecessor}")]
    DuplicatePredecessor {
        handle: ArtifactId,
        predecessor: ArtifactId,
    },
    #[error("record {handle} references missing predecessor {predecessor}")]
    MissingPredecessor {
        handle: ArtifactId,
        predecessor: ArtifactId,
    },
    #[error("record {handle} has a scope different from the requested scope")]
    ScopeMismatch { handle: ArtifactId },
    #[error("record {handle} is not compatible with the requested state fence")]
    FenceMismatch { handle: ArtifactId },
    #[error("requested state fence is invalid")]
    InvalidFence,
    #[error("record {handle} has invalid evidence: {reason}")]
    InvalidEvidence { handle: ArtifactId, reason: String },
    #[error("inquiry {0} must be non-blank")]
    InvalidInquiry(String),
}

fn text(value: &str, field: &'static str) -> Result<(), EpistemicError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(EpistemicError::InvalidText { field })
    } else {
        Ok(())
    }
}

/// The resolver's position algebra. `Assumed` is deliberately a position
/// state, not a promotion of the underlying `EpistemicStatus` vocabulary.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PositionState {
    Observed,
    Supported,
    Assumed,
    Conflicted,
    Stale,
    Unknown,
}

/// One immutable candidate supplied by the canonical semantic owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicRecord {
    pub handle: ArtifactId,
    pub subject: String,
    pub scope: String,
    pub evidence: EvidenceEnvelope,
    /// Exact predecessors retained even when this record is current.
    pub supersedes: Vec<ArtifactId>,
    /// Explicit inquiry or interpretation note; never treated as evidence.
    pub note: Option<String>,
}

impl EpistemicRecord {
    pub fn validate(
        &self,
        requested_scope: &str,
        fence: &StateFence,
    ) -> Result<(), EpistemicError> {
        text(self.subject.as_str(), "record.subject")?;
        text(self.scope.as_str(), "record.scope")?;
        if self.scope != requested_scope {
            return Err(EpistemicError::ScopeMismatch {
                handle: self.handle.clone(),
            });
        }
        if !self.evidence.state_fence.is_compatible_with(fence) {
            return Err(EpistemicError::FenceMismatch {
                handle: self.handle.clone(),
            });
        }
        self.evidence
            .validate()
            .map_err(|source| EpistemicError::InvalidEvidence {
                handle: self.handle.clone(),
                reason: source.to_string(),
            })?;
        let mut predecessors = BTreeSet::new();
        for predecessor in &self.supersedes {
            if predecessor == &self.handle {
                return Err(EpistemicError::SelfSupersession {
                    handle: self.handle.clone(),
                });
            }
            if !predecessors.insert(predecessor.clone()) {
                return Err(EpistemicError::DuplicatePredecessor {
                    handle: self.handle.clone(),
                    predecessor: predecessor.clone(),
                });
            }
        }
        if let Some(note) = &self.note {
            text(note, "record.note")?;
        }
        Ok(())
    }
}

/// A bounded resolver request. Records must already be admitted by the
/// canonical owner; this type only performs deterministic semantic resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositionRequest {
    pub question: String,
    pub scope: String,
    pub state_fence: StateFence,
    pub records: Vec<EpistemicRecord>,
}

impl PositionRequest {
    pub fn validate(&self) -> Result<(), EpistemicError> {
        text(self.question.as_str(), "question")?;
        text(self.scope.as_str(), "scope")?;
        self.state_fence
            .validate()
            .map_err(|_| EpistemicError::InvalidFence)?;
        if self.records.is_empty() {
            return Err(EpistemicError::EmptyInput);
        }
        let mut handles = BTreeSet::new();
        for record in &self.records {
            if !handles.insert(record.handle.clone()) {
                return Err(EpistemicError::DuplicateHandle(record.handle.clone()));
            }
            record.validate(self.scope.as_str(), &self.state_fence)?;
        }
        for record in &self.records {
            for predecessor in &record.supersedes {
                if !handles.contains(predecessor) {
                    return Err(EpistemicError::MissingPredecessor {
                        handle: record.handle.clone(),
                        predecessor: predecessor.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Exact provenance closure for the returned position.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceView {
    pub record_handles: Vec<ArtifactId>,
    pub source_ids: Vec<String>,
    pub raw_handles: Vec<String>,
    pub revisions: Vec<String>,
    pub mixed_sources: bool,
    pub assertability: Assertability,
}

/// The best currently supported position, with rivals and inquiry preserved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurrentEpistemicPosition {
    pub question: String,
    pub scope: String,
    pub state_fence: StateFence,
    pub state: PositionState,
    pub direct_observations: Vec<ArtifactId>,
    pub supporting_records: Vec<ArtifactId>,
    pub rival_records: Vec<ArtifactId>,
    pub stale_records: Vec<ArtifactId>,
    pub superseded_records: Vec<ArtifactId>,
    pub unknowns: Vec<String>,
    pub required_inquiry: Vec<String>,
    pub provenance: ProvenanceView,
}
