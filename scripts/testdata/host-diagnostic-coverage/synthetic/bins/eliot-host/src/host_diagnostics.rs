//! Synthetic Host diagnostic facade (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: the single tracing facade of the synthetic tree,
//! holding the bounded field/detail ceilings every synthetic boundary reuses.

use std::sync::OnceLock;

/// Bounded field byte ceiling shared by every synthetic boundary.
pub const MAX_DIAGNOSTIC_FIELD_BYTES: usize = 96;

/// Bounded detail byte ceiling shared by every synthetic boundary.
pub const MAX_DIAGNOSTIC_DETAIL_BYTES: usize = 192;

/// Terminal code for a rejected console request.
pub const HOST_TERMINAL_CODE_CONSOLE_FAILED: &str = "console_failed";

/// Terminal code for a rejected start request.
pub const HOST_TERMINAL_CODE_START_REQUEST: &str = "start_request_failed";

/// Terminal code for a failed start result.
pub const HOST_TERMINAL_CODE_START_RESULT: &str = "start_result_failed";

/// Process-global subscriber installed exactly once by the binary contour.
static SUBSCRIBER: OnceLock<()> = OnceLock::new();

/// Install the one process subscriber for the whole contour.
pub fn install_host_diagnostics() {
    let _ = SUBSCRIBER.get_or_init(|| ());
}

/// Record a non-terminal entrypoint stage.
pub fn observe_entrypoint(detail: &str) {
    tracing::info!(detail, "host.entrypoint_stage");
}

/// Record the single terminal record of one failed underlying operation.
pub fn observe_terminal_error(code: &str) {
    tracing::error!(code, "host.terminal_error");
}

/// Record an owner-projected request record.
pub fn observe_host_request(correlation: &str) {
    tracing::info!(correlation, "host.request");
}
