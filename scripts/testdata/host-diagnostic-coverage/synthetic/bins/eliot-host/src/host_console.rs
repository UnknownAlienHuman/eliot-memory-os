//! Synthetic Host console contour (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: the console contour that observes the
//! entrypoint stage and hands the typed rejection to the binary emitter.

use crate::host_diagnostics::observe_entrypoint;

/// Admit one console request through the synthetic contour.
pub fn admit_console_request(request: &str) -> Result<String, String> {
    observe_entrypoint(request);
    if request.is_empty() {
        return Err("console.rejected".to_owned());
    }
    Ok(request.to_owned())
}
