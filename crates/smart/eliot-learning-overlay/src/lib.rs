//! Pure composition of a bounded, task-local learning overlay candidate.
//!
//! This crate consumes an immutable A-32 state view and an exact set of
//! externally admitted-for-evaluation A-32 delta candidates. It never admits,
//! activates, delivers, evaluates, persists, or promotes an overlay. The
//! supported prototype only changes deterministic verification ordering and
//! search/probe stopping surfaces; broader protected-owner evidence remains an
//! integration gap because the current A-32 contracts do not carry those fields.
//! The two supported surface labels are A-32 enum values; they do not prove a
//! target-to-surface schema or protected payload. Protected-surface digests in
//! the input are caller-supplied equality assertions, not recomputed policy
//! evidence.

#![forbid(unsafe_code)]

mod base;
mod bounds;
mod changes;
mod compose;

use eliot_contracts::{ArtifactId, TaskRevision};
use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, CampaignHarnessOverlayCandidate, CampaignLearningStateView,
    LearningStateViewRecipe,
};
use thiserror::Error;

pub use compose::compose_campaign_harness_overlay;

/// Maximum delta candidates in one pure composition.
pub const MAX_DELTAS: usize = 128;
/// Maximum changes in one candidate.
pub const MAX_CHANGES: usize = 128;
/// Maximum explicit references retained by one candidate input.
pub const MAX_REFERENCES: usize = 1024;
/// Maximum aggregate input text inspected before owner validation.
pub const MAX_INPUT_TEXT_BYTES: usize = 1_048_576;
/// Conservative output expansion ceiling before canonical candidate sealing.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum bounded composition work units before allocating candidate output.
pub const MAX_WORK_UNITS: usize = 1_000_000;

/// An externally supplied identity/digest assertion for one admitted delta.
///
/// The overlay composer checks that this pair exactly names one supplied
/// candidate. It does not authenticate the assertion or own admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedDeltaPair {
    /// Candidate artifact identity.
    pub delta_id: ArtifactId,
    /// Candidate canonical digest.
    pub canonical_digest: String,
}

/// Borrowed immutable inputs and caller-supplied candidate metadata.
pub struct OverlayComposeInput<'a> {
    /// Exact recipe used to validate the base view.
    pub recipe: &'a LearningStateViewRecipe,
    /// Immutable state view being overlaid.
    pub view: &'a CampaignLearningStateView,
    /// Exact selected candidates externally admitted for evaluation.
    pub deltas: &'a [AttemptLearningDeltaCandidate],
    /// External identity/digest assertions, with no local admission meaning.
    pub admitted: &'a [AdmittedDeltaPair],
    /// New candidate identity.
    pub overlay_id: eliot_learning_contracts::OverlayId,
    /// Parent task revision; must equal the view fence task revision.
    pub parent_revision: TaskRevision,
    /// Caller-supplied protected-surface digest before composition.
    pub protected_surface_base_digest: &'a str,
    /// Caller-supplied protected-surface digest after composition.
    pub protected_surface_proposed_digest: &'a str,
    /// Discriminator fixed before any observation.
    pub fixed_before_observation_discriminator: &'a ArtifactId,
    /// Candidate expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Explicit caller observation time used only for expiry comparison.
    pub observed_at_ms: u64,
}

/// Result errors retain stable phase/field classes without payload text.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OverlayError {
    /// An existing A-32 contract rejected an input or candidate.
    #[error(transparent)]
    Contract(#[from] eliot_learning_contracts::LearningContractError),
    /// A bounded input or output expansion was rejected.
    #[error("{field} exceeds the overlay bound")]
    Bound { field: &'static str },
    /// The requested A-32 shape is not representable by this composer.
    #[error("{field} is unsupported by the overlay composer")]
    Unsupported { field: &'static str },
    /// Two supplied candidates claim the same effective surface incompatibly.
    #[error("{field} contains a conflicting overlay change")]
    Conflict { field: &'static str },
    /// A candidate expired before this pure observation.
    #[error("overlay candidate expired")]
    Expired,
    /// A protected surface digest changed.
    #[error("protected overlay surface changed")]
    ProtectedSurfaceChanged,
}

/// Direct candidate output retained for callers that need an explicit type.
pub type OverlayCandidate = CampaignHarnessOverlayCandidate;
