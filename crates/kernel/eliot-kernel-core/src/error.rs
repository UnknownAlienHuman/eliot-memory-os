//! Kernel-control failures that never carry secret material or raw process output.
//!
//! Every variant is a stable, transportable reason code. The Kernel decision
//! core returns these failures instead of panicking or fabricating authority,
//! so a consumer can surface an exact reason without crossing the secret
//! boundary.

use eliot_contracts::ContractError;
use eliot_process::ContractError as ProcessContractError;
use eliot_receipts::ReceiptError;
use eliot_runtime_contracts::RuntimeContractError;
use thiserror::Error;

/// Typed failure surface owned by the Kernel decision core.
#[derive(Debug, Error)]
pub enum KernelError {
    /// A shared C0-01 primitive rejected its value.
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),

    /// A C0-02 receipt binding was invalid.
    #[error("receipt contract: {0}")]
    Receipt(#[from] ReceiptError),

    /// A C0-04 runtime contract binding was invalid.
    #[error("runtime contract: {0}")]
    RuntimeContract(#[from] RuntimeContractError),

    /// A P-03 process contract binding was invalid.
    #[error("process contract: {0}")]
    ProcessContract(#[from] ProcessContractError),

    /// A P-06 durable recovery-state operation failed.
    #[error("operational recovery state: {0}")]
    RecoveryState(#[from] eliot_ors::OrsError),

    /// A required textual field is blank or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },

    /// The presented authority receipt failed its cryptographic binding.
    #[error("authority receipt is forged or tampered")]
    ForgedReceipt,

    /// The presented authority receipt belongs to a fenced (stale) epoch.
    #[error("authority receipt epoch {observed} does not match active epoch {active}")]
    StaleEpoch {
        /// Epoch presented by the receipt.
        observed: u64,
        /// Epoch the Kernel is currently fencing.
        active: u64,
    },

    /// The presented authority receipt targets a different route.
    #[error("authority receipt route does not match the requested route")]
    RouteMismatch,

    /// The presented authority receipt has expired.
    #[error("authority receipt expired at {expires_at_ms}")]
    Expired {
        /// Expiry timestamp in Unix milliseconds.
        expires_at_ms: i64,
    },

    /// The request fence does not match the current route fence.
    #[error("route fence mismatch")]
    FenceMismatch,

    /// A lifecycle transition is not admitted by the owned machine.
    #[error("illegal {machine} transition from {from} to {to}")]
    IllegalTransition {
        /// Machine label.
        machine: &'static str,
        /// Current state.
        from: String,
        /// Requested state.
        to: String,
    },

    /// The control reserve is exhausted; no control permit can be granted.
    #[error("control reserve exhausted")]
    ControlReserveExhausted,

    /// An idempotency key conflicts with a prior, different request.
    #[error("idempotency key conflict")]
    IdempotencyConflict,

    /// A durable dependency is missing or unavailable.
    #[error("dependency unavailable: {0}")]
    DependencyUnavailable(String),

    /// A durable recovery projection is unavailable or unverified.
    #[error("recovery view unavailable: {0}")]
    RecoveryUnavailable(String),
}

/// Compatibility name for consumers that spell the kernel failure a result.
pub type KernelResult<T> = Result<T, KernelError>;

/// Internal helper shared by the authority modules for opaque-text validation.
pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), KernelError> {
    if value.trim().is_empty() {
        return Err(KernelError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(KernelError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

/// Internal helper shared by the authority modules for opaque-identity validation.
pub(crate) fn validate_id(value: &str, field: &'static str) -> Result<(), KernelError> {
    validate_text(value, field)?;
    if value.len() > 1_024 {
        return Err(KernelError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}
