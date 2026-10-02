//! Synthetic Host SCM receipt owner (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: the persisted SCM receipt correlation, whose
//! payload projection is an absence span (protected payload never projected).

use crate::host_diagnostics::observe_host_request;

/// Persisted SCM receipt correlation owned by the launch contour.
pub struct ScmReceipt {
    pub process_id: u32,
    pub generation: u64,
}

/// Record the persisted receipt correlation for one admitted request.
pub fn record_receipt(receipt: &ScmReceipt) {
    observe_host_request(&format!(
        "scm_receipt process={} generation={}",
        receipt.process_id, receipt.generation
    ));
}

/// Protected payload bytes: never projected into any diagnostic record.
pub fn protected_payload() -> &'static str {
    "scm_protected_payload"
}
