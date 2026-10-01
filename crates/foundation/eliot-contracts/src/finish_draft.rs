//! Shared eliot.finish.candidate data; Governor retains semantic authority.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Caller-requested finish candidate.  It contains no completion proof.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishAttemptDraft {
    /// Task identity selected by the caller.
    pub task_id: String,
    /// Exact current task revision expected by the caller.
    pub expected_task_revision: u64,
    /// Candidate outcome; Governor derives the decision.
    pub requested_outcome: RequestedFinishOutcome,
    /// Immutable artifact handles.
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    /// Observation handles.
    #[serde(default)]
    pub observation_refs: Vec<String>,
    /// Executed verifier-run handles.
    #[serde(default)]
    pub verifier_run_refs: Vec<String>,
    /// Unknowns disclosed by the caller.
    #[serde(default)]
    pub remaining_unknowns_declared_by_caller: Vec<String>,
    /// Public rationale candidate.
    pub rationale_candidate: String,
}

/// Caller-requested finish outcome.  It is never persisted as the decision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestedFinishOutcome {
    /// Request evaluation for complete work.
    CompleteCandidate,
    /// Declare partial work.
    Partial,
    /// Declare a blocker.
    Blocked,
    /// Declare a verification failure.
    FailedVerification,
    /// Declare degraded proof.
    DegradedNoProof,
    /// Declare that finishing would be unsafe.
    UnsafeToFinish,
    /// Declare cancellation.
    Cancelled,
    /// Declare supersession.
    Superseded,
}

/// Typed shape refusal for the shared candidate; it grants no Finish authority.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FinishDraftValidationError {
    /// A required candidate field is malformed.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Exact candidate field path.
        field: &'static str,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// A candidate reference list contains the same handle twice.
    #[error("duplicate values in {field}")]
    Duplicate {
        /// Exact candidate list path.
        field: &'static str,
    },
}

impl FinishAttemptDraft {
    /// Validates the original strict candidate shape without deriving proof.
    pub fn validate(&self) -> Result<(), FinishDraftValidationError> {
        candidate_text(&self.task_id, "finish.task_id")?;
        if self.expected_task_revision == 0 {
            return Err(FinishDraftValidationError::InvalidField {
                field: "finish.expected_task_revision",
                reason: "must be non-zero",
            });
        }
        candidate_text(&self.rationale_candidate, "finish.rationale_candidate")?;
        for (values, field) in [
            (&self.artifact_refs, "finish.artifact_refs"),
            (&self.observation_refs, "finish.observation_refs"),
            (&self.verifier_run_refs, "finish.verifier_run_refs"),
            (
                &self.remaining_unknowns_declared_by_caller,
                "finish.remaining_unknowns_declared_by_caller",
            ),
        ] {
            let mut seen = std::collections::BTreeSet::new();
            for value in values {
                candidate_text(value, field)?;
                if !seen.insert(value) {
                    return Err(FinishDraftValidationError::Duplicate { field });
                }
            }
        }
        Ok(())
    }
}

fn candidate_text(value: &str, field: &'static str) -> Result<(), FinishDraftValidationError> {
    crate::validate_text(value, field).map_err(|_| FinishDraftValidationError::InvalidField {
        field,
        reason: "must be non-blank and contain no control characters",
    })
}
