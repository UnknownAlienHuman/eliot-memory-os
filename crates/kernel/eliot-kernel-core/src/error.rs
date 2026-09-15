//! Kernel-control failures that never carry secret material or raw process output.
//!
//! Every variant is a stable, transportable reason code. The Kernel decision
//! core returns these failures instead of panicking or fabricating authority,
//! so a consumer can surface an exact reason without crossing the secret
//! boundary.

use eliot_contracts::{AuthorityEpoch, ContractError};
use eliot_process::ContractError as ProcessContractError;
use eliot_receipts::ReceiptError;
use eliot_runtime_contracts::RuntimeContractError;
use thiserror::Error;

use crate::module::control_reserve_front_door::{
    CapacityBottleneck, ControlOperationClass, EmergencyOperationClass, NormalWorkClass,
};

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
    ///
    /// Migration-only surface for pre-slice-A callers (`FrontDoor::acquire_control`,
    /// `FrontDoor::authorize`) that hold the protected partition without a typed
    /// operation binding. New callers must use the typed partition acquisitions on
    /// [`crate::FrontDoor`] and receive the per-bottleneck dispositions below.
    /// Slice B (issue #65 service wave) migrates the remaining legacy holders.
    #[error("control reserve exhausted")]
    ControlReserveExhausted,

    /// Normal workload admission is backpressured at the named bottleneck.
    ///
    /// The protected and emergency partitions are untouched by this disposition
    /// (contract `BACKPRESSURED_NORMAL`, issue #65): saturating normal work leaves
    /// demonstrable capacity for cancellation, fencing, health, drain,
    /// problem/incident and recovery. Callers shed, defer or quarantine the named
    /// normal work; they must not retry it against the protected reserve.
    #[error(
        "normal capacity exhausted at {bottleneck:?} for {work_class:?} operation {operation_id} owner {owner} epoch {epoch:?}: backpressure normal work"
    )]
    NormalCapacityExhausted {
        /// Bottleneck whose normal partition is saturated.
        bottleneck: CapacityBottleneck,
        /// Normal work class that was shed.
        work_class: NormalWorkClass,
        /// Operation that was denied admission.
        operation_id: String,
        /// Owner that requested admission.
        owner: String,
        /// Front-door epoch observed at denial.
        epoch: AuthorityEpoch,
    },

    /// The protected control reserve is exhausted at the named bottleneck.
    ///
    /// Only closed [`ControlOperationClass`] operations can observe this
    /// disposition (contract `PROTECTED_RESERVE_EXHAUSTED`, issue #65). Normal
    /// work is never admitted through this path: a normal Store write, named
    /// read, agent admission or module job cannot construct the typed request.
    #[error(
        "protected reserve exhausted at {bottleneck:?} for {operation:?} operation {operation_id} owner {owner} epoch {epoch:?}"
    )]
    ProtectedReserveExhausted {
        /// Bottleneck whose protected partition is saturated.
        bottleneck: CapacityBottleneck,
        /// Control operation that was denied the reserve.
        operation: ControlOperationClass,
        /// Operation that was denied admission.
        operation_id: String,
        /// Owner that requested admission.
        owner: String,
        /// Front-door epoch observed at denial.
        epoch: AuthorityEpoch,
    },

    /// The preallocated emergency last-resort slot is unavailable.
    ///
    /// Emitted while a protected path still remains to record the gap (contract
    /// `EMERGENCY_SLOT_UNAVAILABLE`, issue #65). Only closed
    /// [`EmergencyOperationClass`] operations (reserve-loss/gap record, entering
    /// manual recovery) can observe this disposition.
    #[error(
        "emergency slot unavailable at {bottleneck:?} for {operation:?} operation {operation_id} owner {owner} epoch {epoch:?}"
    )]
    EmergencySlotUnavailable {
        /// Bottleneck whose emergency slot is held.
        bottleneck: CapacityBottleneck,
        /// Emergency operation that was denied the slot.
        operation: EmergencyOperationClass,
        /// Operation that was denied admission.
        operation_id: String,
        /// Owner that requested admission.
        owner: String,
        /// Front-door epoch observed at denial.
        epoch: AuthorityEpoch,
    },

    /// No control path remains: the system explicitly loses its control guarantee.
    ///
    /// Emitted when the emergency last-resort slot is unavailable and the
    /// protected reserve is also exhausted, so the gap cannot be recorded through
    /// any remaining path (A13.5, I14.3, contract `CONTROL_GUARANTEE_LOST`,
    /// issue #65). This is an incident/manual-recovery boundary, never a
    /// warning-only metric and never a healthy status.
    #[error("control guarantee lost at {bottleneck:?}: {detail}")]
    ControlGuaranteeLost {
        /// Bottleneck at which the last-resort path was lost.
        bottleneck: CapacityBottleneck,
        /// Exact lost guarantee for post-recovery recording.
        detail: String,
    },

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
