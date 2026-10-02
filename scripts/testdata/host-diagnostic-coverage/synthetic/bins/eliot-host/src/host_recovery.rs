//! Synthetic Host recovery helper (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: a helper that propagates into the launch
//! terminal boundary without emitting a diagnostic of its own.

use crate::host_launch_options::reject_installation;

/// Propagate a rejected installation into the launch terminal boundary.
pub fn recover_installation(raw: &str) -> Result<(), String> {
    reject_installation(raw)?;
    Ok(())
}
