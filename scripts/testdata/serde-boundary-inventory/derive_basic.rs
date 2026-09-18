//! Fixture: single-line strict derive (case 1/4/10 baseline).
//! Package-neutral synthetic source; scanner must produce exactly one
//! current-closed candidate with deny_unknown_fields evidence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicRecord {
    pub identity: String,
    pub scope: String,
    pub authority: String,
}
