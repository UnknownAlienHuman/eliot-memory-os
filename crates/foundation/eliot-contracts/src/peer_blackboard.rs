//! Owner-neutral category and lifecycle values for shared peer blackboard items.
//!
//! These values identify retained candidate records only. They do not grant
//! task acceptance, truth, or effect authority.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Closed blackboard item vocabulary (I10.18).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeerBoardKind {
    FindingCandidate,
    EvidenceHandle,
    Unknown,
    HypothesisCandidate,
    ConflictNotice,
    DecisionRequest,
    VerifierResult,
    ArtifactHandle,
    Blocker,
}

impl PeerBoardKind {
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::FindingCandidate => "finding_candidate",
            Self::EvidenceHandle => "evidence_handle",
            Self::Unknown => "unknown",
            Self::HypothesisCandidate => "hypothesis_candidate",
            Self::ConflictNotice => "conflict_notice",
            Self::DecisionRequest => "decision_request",
            Self::VerifierResult => "verifier_result",
            Self::ArtifactHandle => "artifact_handle",
            Self::Blocker => "blocker",
        }
    }

    /// Closed decode: unknown spellings are rejected, never coerced.
    pub fn decode(text: &str) -> Result<Self, PeerBoardKindError> {
        match text {
            "finding_candidate" => Ok(Self::FindingCandidate),
            "evidence_handle" => Ok(Self::EvidenceHandle),
            "unknown" => Ok(Self::Unknown),
            "hypothesis_candidate" => Ok(Self::HypothesisCandidate),
            "conflict_notice" => Ok(Self::ConflictNotice),
            "decision_request" => Ok(Self::DecisionRequest),
            "verifier_result" => Ok(Self::VerifierResult),
            "artifact_handle" => Ok(Self::ArtifactHandle),
            "blocker" => Ok(Self::Blocker),
            _ => Err(PeerBoardKindError::Unknown(text.to_owned())),
        }
    }

    #[must_use]
    pub const fn all() -> [&'static str; 9] {
        [
            "finding_candidate",
            "evidence_handle",
            "unknown",
            "hypothesis_candidate",
            "conflict_notice",
            "decision_request",
            "verifier_result",
            "artifact_handle",
            "blocker",
        ]
    }
}

/// Failure to decode a closed blackboard item category.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PeerBoardKindError {
    /// The spelling is outside the exact I10.18 category set.
    #[error("unknown blackboard item kind: {0}")]
    Unknown(String),
}

/// Lifecycle of one retained blackboard item head. History is retained
/// through revisions; retracted heads remain visible to readers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum BoardEntryState {
    Current,
    Superseded { by_revision: u64 },
    Retracted { by_session: String, at: u64 },
}
