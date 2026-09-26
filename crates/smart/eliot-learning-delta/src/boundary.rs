//! Consequential-boundary trigger classifier (issue #1863, doc I12.24).
//!
//! A consequential boundary is a material implementation attempt, a verifier
//! outcome, a substantial recovery attempt, a repeated failure signature, a
//! campaign checkpoint or plateau, a route/model handoff, an accepted artifact
//! outcome, a finish/cancel/supersession, or a delayed regression. A
//! `read_file` or `grep` is not consequential.
//!
//! The classification is *derived* from [`LifecycleActivity`] values an owner
//! recorded, never from a caller-asserted boundary: naming a
//! [`ConsequentialBoundary`] value alone authorizes nothing. [`derive_boundaries`]
//! is the only entry that turns observed activities into boundaries, it
//! applies the ordinary-read exclusion through [`status_for_tool`], and an
//! ordinary read is refused there even when other activities were observed.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AttemptStatus, LearningDeltaError};

/// The nine trigger classes that may authorize learning-delta derivation.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
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

    /// Boundary class implied by one observed lifecycle activity.
    ///
    /// The mapping is total and one-to-one: every activity an owner can record
    /// names exactly one boundary, so a recorded activity is never ambiguous
    /// and never leaves the closed nine-value vocabulary.
    pub const fn of(activity: LifecycleActivity) -> Self {
        match activity {
            LifecycleActivity::MaterialImplementationAttempt => Self::MaterialImplementationAttempt,
            LifecycleActivity::VerifierOutcome => Self::VerifierOutcome,
            LifecycleActivity::SubstantialRecovery => Self::SubstantialRecovery,
            LifecycleActivity::RepeatedFailureSignature => Self::RepeatedFailureSignature,
            LifecycleActivity::CampaignCheckpointPlateau => Self::CampaignCheckpointPlateau,
            LifecycleActivity::RouteModelHandoff => Self::RouteModelHandoff,
            LifecycleActivity::AcceptedArtifactOutcome => Self::AcceptedArtifactOutcome,
            LifecycleActivity::AttemptSettled => Self::FinishCancelSupersession,
            LifecycleActivity::DelayedRegression => Self::DelayedRegression,
        }
    }
}

/// One lifecycle activity an owner actually recorded for an attempt.
///
/// This is the closed input vocabulary of [`derive_boundaries`]. A caller that
/// cannot name a recorded activity has no consequential boundary, and the
/// ordinary-read exclusion applies before any activity is considered.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleActivity {
    /// A material implementation attempt reached execution.
    MaterialImplementationAttempt,
    /// A verifier produced a finished outcome for the attempt.
    VerifierOutcome,
    /// A repeated attempt substantially recovered the work.
    SubstantialRecovery,
    /// A failure signature repeated across physical attempts.
    RepeatedFailureSignature,
    /// A campaign checkpoint or plateau was reached.
    CampaignCheckpointPlateau,
    /// A route or model handoff transferred the work.
    RouteModelHandoff,
    /// A verifier outcome was accepted for the produced artifact.
    AcceptedArtifactOutcome,
    /// The attempt finished, was cancelled, or was superseded.
    AttemptSettled,
    /// A delayed regression surfaced after the attempt.
    DelayedRegression,
}

impl LifecycleActivity {
    /// Every observable lifecycle activity, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::MaterialImplementationAttempt,
        Self::VerifierOutcome,
        Self::SubstantialRecovery,
        Self::RepeatedFailureSignature,
        Self::CampaignCheckpointPlateau,
        Self::RouteModelHandoff,
        Self::AcceptedArtifactOutcome,
        Self::AttemptSettled,
        Self::DelayedRegression,
    ];

    /// Snake-case name of this observed activity.
    pub const fn as_str(self) -> &'static str {
        self.boundary().as_str()
    }

    /// The boundary class this activity implies.
    pub const fn boundary(self) -> ConsequentialBoundary {
        ConsequentialBoundary::of(self)
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
/// `Some` boundary maps to [`AttemptStatus::Consequential`]; `None` means no
/// boundary was supplied and maps to [`AttemptStatus::NonConsequential`]. This
/// helper reports a caller's own label only; it is never an authorization to
/// derive, which is [`derive_boundaries`] plus the evidence-bound derivation.
pub fn status_for_boundary(boundary: Option<ConsequentialBoundary>) -> AttemptStatus {
    match boundary {
        Some(boundary) => boundary.status(),
        None => AttemptStatus::NonConsequential,
    }
}

/// Maps a recorded activity name to an attempt status.
///
/// The ordinary-read exclusion is the only tool-level rule I12.24 states, and
/// this function applies it: an ordinary read maps to
/// [`AttemptStatus::NonConsequential`] and every other recorded activity name
/// maps to [`AttemptStatus::Consequential`] because it is *not* excluded by
/// that rule.
///
/// A consequential tool verdict is still not an authorization to derive.
/// [`derive_boundaries`] additionally requires at least one recorded
/// [`LifecycleActivity`], and the derivation wrapper additionally requires a
/// bound evidence bundle, so no tool name alone can produce a delta.
pub fn status_for_tool(tool_name: &str) -> AttemptStatus {
    if is_non_consequential_tool(tool_name) {
        AttemptStatus::NonConsequential
    } else {
        AttemptStatus::Consequential
    }
}

/// Derive the consequential boundaries one attempt actually crossed.
///
/// `activity_name` is the activity/tool identity an owner recorded for the
/// observed step; `observed` are the lifecycle activities the same owner
/// recorded. Returns the derived boundaries in [`ConsequentialBoundary::ALL`]
/// order.
///
/// Fails closed with [`LearningDeltaError::NonConsequential`] when the recorded
/// activity is an ordinary read (the I12.24 read exclusion, applied through
/// [`status_for_tool`]) or when no lifecycle activity was recorded at all, and
/// with [`LearningDeltaError::InvalidInput`] when the recorded activity name is
/// blank.
pub fn derive_boundaries(
    activity_name: &str,
    observed: &[LifecycleActivity],
) -> Result<Vec<ConsequentialBoundary>, LearningDeltaError> {
    if activity_name.trim().is_empty() {
        return Err(LearningDeltaError::InvalidInput {
            field: "boundary.activity",
        });
    }
    if status_for_tool(activity_name) == AttemptStatus::NonConsequential {
        return Err(LearningDeltaError::NonConsequential);
    }
    if observed.is_empty() {
        return Err(LearningDeltaError::NonConsequential);
    }
    let recorded: std::collections::BTreeSet<ConsequentialBoundary> = observed
        .iter()
        .map(|activity| activity.boundary())
        .collect();
    Ok(ConsequentialBoundary::ALL
        .into_iter()
        .filter(|boundary| recorded.contains(boundary))
        .collect())
}

/// Requires at least one derived consequential boundary for derivation.
///
/// Returns the first derived boundary of `boundaries`, or
/// [`LearningDeltaError::NonConsequential`] when the derivation is empty.
pub fn require_consequential(
    boundaries: &[ConsequentialBoundary],
) -> Result<ConsequentialBoundary, LearningDeltaError> {
    boundaries
        .first()
        .copied()
        .ok_or(LearningDeltaError::NonConsequential)
}
