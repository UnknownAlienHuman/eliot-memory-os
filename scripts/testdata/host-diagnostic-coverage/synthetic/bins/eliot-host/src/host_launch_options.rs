//! Synthetic Host launch owner (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: the typed rejection site the start contour calls.

use crate::host_diagnostics::{HOST_TERMINAL_CODE_START_REQUEST, observe_terminal_error};

/// Reject an installation identifier the launch owner cannot admit.
pub fn reject_installation(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        observe_terminal_error(HOST_TERMINAL_CODE_START_REQUEST);
        return Err("launch.rejected".to_owned());
    }
    Ok(())
}
