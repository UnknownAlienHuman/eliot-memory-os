//! Stable Orientation dispositions and operation result.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::input::OrientationError;
use crate::projection::OrientationPacketCandidate;

/// Closed projection dispositions. None implies delivery, truth or authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OrientationDisposition {
    Complete,
    Partial,
    Blocked,
    RevalidationRequired,
    Unsupported,
    Abstention,
    Cancelled,
    Bound,
    Invalid,
    Internal,
}

/// Result of one immutable Orientation projection.
pub type OrientationResult = Result<OrientationPacketCandidate, OrientationError>;

/// Closed per-stage disposition for one Orientation pulse member (issue #2901).
///
/// The composer emits `Executed` for a stage whose owner entry ran,
/// `Pending` for a compatibility-composition member whose owner inputs were
/// absent, and `Blocked` for a production member that cannot proceed (missing
/// prerequisite, incoherent closure, or owner refusal). `Stale`, `Unknown`,
/// and `NotApplicable` are versioned contract states for owner-reported
/// conditions; no current owner reports them, so the composer never emits
/// them today.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrientationStageDisposition {
    Executed,
    Pending,
    Blocked,
    Stale,
    Unknown,
    NotApplicable,
}
