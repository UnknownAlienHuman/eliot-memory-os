//! Stable identity of one observed filesystem file object.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub volume_serial_number: u32,
    pub file_index: u64,
}
