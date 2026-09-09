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
