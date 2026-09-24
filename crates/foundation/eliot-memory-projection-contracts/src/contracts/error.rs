//! Typed validation failures for the memory projection contracts.
//!
//! Errors name only the failing field and the violated rule. They never echo
//! record content, digests, or scope identities.

use eliot_contracts::ContractError;
use eliot_evidence::EvidenceError;
use eliot_receipts::ReceiptError;
use thiserror::Error;

/// Validation failure for a memory projection record, batch, or set.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MemoryProjectionError {
    /// A shared C0-01 primitive rejected its value.
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    /// A receipt contract rejected a shared scope binding.
    #[error("receipt contract: {0}")]
    Receipt(#[from] ReceiptError),
    /// An evidence contract rejected shared epistemic material.
    #[error("evidence contract: {0}")]
    Evidence(#[from] EvidenceError),
    /// A required field is absent or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Field that failed validation.
        field: &'static str,
        /// Short machine-stable rule description.
        reason: &'static str,
    },
    /// A bounded collection holds too many members.
    #[error("{field} exceeds its bound")]
    Bounds {
        /// Field that exceeded its bound.
        field: &'static str,
    },
    /// A collection that must be unique contains a duplicate handle.
    #[error("{field} contains duplicate value {value}")]
    Duplicate {
        /// Field that contains the duplicate.
        field: &'static str,
        /// Duplicated handle text.
        value: String,
    },
    /// Two bindings that must share one fence disagree.
    #[error("{left} and {right} have incompatible StateFences")]
    FenceMismatch {
        /// Left side of the comparison.
        left: &'static str,
        /// Right side of the comparison.
        right: &'static str,
    },
    /// A record binding does not equal the batch binding.
    #[error("record binding does not match the batch binding: {reason}")]
    ScopeMismatch {
        /// Short machine-stable rule description.
        reason: &'static str,
    },
    /// A record names a contract version this crate cannot read.
    #[error("unsupported contract version")]
    VersionMismatch,
    /// Coverage accounting contradicts the carried members.
    #[error("coverage accounting is inconsistent: {reason}")]
    CoverageMismatch {
        /// Short machine-stable rule description.
        reason: &'static str,
    },
}
