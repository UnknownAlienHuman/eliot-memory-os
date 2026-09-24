//! Consequential-boundary trigger classifier (issue #1863, doc I12.24).
//!
//! A consequential boundary is a material implementation attempt, a verifier
//! outcome, a substantial recovery attempt, a repeated failure signature, a
//! campaign checkpoint or plateau, a route/model handoff, an accepted artifact
//! outcome, a finish/cancel/supersession, or a delayed regression. A
//! `read_file` or `grep` is not consequential.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AttemptStatus, LearningDeltaError};

/// The nine trigger classes that may authorize learning-delta derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsequentialBoundary {
    /// A material implementation attempt reached execution.
    MaterialImplementationAttempt,
    /// A verifier produced an outcome for the attempt.
    VerifierOutcome,
    /// A substantial recovery attempt was undertaken.
    SubstantialRecovery,
    /// A failure signature repeated across attempts.
    RepeatedFailureSignature,
    /// A campaign checkpoint or plateau was reached.
    CampaignCheckpointPlateau,
    /// A route or model handoff transferred the work.
    RouteModelHandoff,
    /// An artifact outcome was accepted.
    AcceptedArtifactOutcome,
    /// The work finished, was cancelled, or was superseded.
    FinishCancelSupersession,
    /// A delayed regression surfaced after the attempt.
    DelayedRegression,
}

impl ConsequentialBoundary {
    /// Every consequential boundary trigger, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::MaterialImplementationAttempt,
        Self::VerifierOutcome,
        Self::SubstantialRecovery,
        Self::RepeatedFailureSignature,
        Self::CampaignCheckpointPlateau,
        Self::RouteModelHandoff,
        Self::AcceptedArtifactOutcome,
        Self::FinishCancelSupersession,
        Self::DelayedRegression,
    ];

    /// Snake-case name of this boundary trigger.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaterialImplementationAttempt => "material_implementation_attempt",
            Self::VerifierOutcome => "verifier_outcome",
            Self::SubstantialRecovery => "substantial_recovery",
            Self::RepeatedFailureSignature => "repeated_failure_signature",
            Self::CampaignCheckpointPlateau => "campaign_checkpoint_plateau",
            Self::RouteModelHandoff => "route_model_handoff",
            Self::AcceptedArtifactOutcome => "accepted_artifact_outcome",
            Self::FinishCancelSupersession => "finish_cancel_supersession",
            Self::DelayedRegression => "delayed_regression",
        }
    }

    /// Attempt status carried by any explicit consequential boundary.
    pub const fn status(self) -> AttemptStatus {
        let _ = self;
        AttemptStatus::Consequential
    }
}

/// Reports whether a tool name is an ordinary read that must never emit deltas.
///
/// Matches exactly `read_file`, `read`, or `grep` after trimming surrounding
/// whitespace, case-insensitively in ASCII. These ordinary reads are not
/// consequential boundaries.
pub fn is_non_consequential_tool(tool_name: &str) -> bool {
    let trimmed = tool_name.trim();
    trimmed.eq_ignore_ascii_case("read_file")
        || trimmed.eq_ignore_ascii_case("read")
        || trimmed.eq_ignore_ascii_case("grep")
}

/// Maps an explicit boundary to its attempt status.
///
/// `Some` boundary authorizes [`AttemptStatus::Consequential`]; `None` means no
/// boundary was supplied and maps to [`AttemptStatus::NonConsequential`].
pub fn status_for_boundary(boundary: Option<ConsequentialBoundary>) -> AttemptStatus {
    match boundary {
        Some(boundary) => boundary.status(),
        None => AttemptStatus::NonConsequential,
    }
}

/// Maps a tool name to an attempt status, fail-closed.
///
/// Ordinary reads map to [`AttemptStatus::NonConsequential`], and every other
/// tool name maps to [`AttemptStatus::NonConsequential`] as well: a tool name
/// alone never authorizes derivation. The caller must supply an explicit
/// [`ConsequentialBoundary`] via [`status_for_boundary`] or
/// [`require_consequential`].
pub fn status_for_tool(tool_name: &str) -> AttemptStatus {
    let _ = is_non_consequential_tool(tool_name);
    AttemptStatus::NonConsequential
}

/// Requires an explicit consequential boundary for derivation.
///
/// Returns the supplied boundary, or [`LearningDeltaError::NonConsequential`]
/// when none was provided.
pub fn require_consequential(
    boundary: Option<ConsequentialBoundary>,
) -> Result<ConsequentialBoundary, LearningDeltaError> {
    boundary.ok_or(LearningDeltaError::NonConsequential)
}
