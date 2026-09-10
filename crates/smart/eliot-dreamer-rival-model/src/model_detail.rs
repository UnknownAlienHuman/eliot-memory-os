//! Bounded per-model source-body rows used by the result packer.

use eliot_dreamer_contracts::rival::RivalModelDeclaration;
use serde::{Deserialize, Serialize};

/// Why a retained model body was left outside the bounded result envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ModelBodyOmissionReason {
    OutputBytes,
    WorkBudget,
}

/// One canonical source-table row for one model slot.
///
/// `SourceSet` points at the body retained in the complete declaration set.
/// The other states are independent packing accounting and carry no model
/// ranking, truth, authority, or execution meaning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum RivalModelDetail {
    SourceSet {
        source_row: u32,
    },
    Retained {
        source_row: u32,
        declaration: Box<RivalModelDeclaration>,
    },
    Omitted {
        source_row: u32,
        reason: ModelBodyOmissionReason,
    },
    Unavailable {
        source_row: u32,
    },
}
