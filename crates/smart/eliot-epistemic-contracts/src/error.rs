//! Closed validation errors and shared bounded-text helpers.
//!
//! Every failure in this crate is a member of [`ContractError`]. The enum is closed: no catch-all variant,
//! and validation never panics. Bounds for variable-length fields live here so every module enforces one ceiling.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde::Serialize;
use thiserror::Error;

/// Maximum length of a short identity/label/coordinate field, in characters.
pub const MAX_SHORT_TEXT: usize = 256;
/// Maximum length of a statement/stance/prose field, in characters.
pub const MAX_STATEMENT_TEXT: usize = 4096;
/// Maximum number of evidence handles carried by one record.
pub const MAX_HANDLES: usize = 64;
/// Maximum number of members carried by one denominator or receipt.
pub const MAX_MEMBERS: usize = 512;
/// Maximum number of positions carried by one conflict set.
pub const MAX_POSITIONS: usize = 32;
/// Maximum byte length admitted for a bounded proof payload.
pub const MAX_PROOF_BYTES: u64 = 65_536;

/// Closed validation failure for every epistemic contract shape.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ContractError {
    /// A required value is empty or consists only of whitespace.
    #[error("{field} must be non-blank")]
    Blank { field: &'static str },
    /// A value contains a control character.
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    /// A variable-length field exceeds its documented ceiling.
    #[error("{field} exceeds the maximum length")]
    TooLong { field: &'static str },
    /// A collection that is required for the record is empty.
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    /// A collection exceeds its documented member ceiling.
    #[error("{field} exceeds the maximum member count")]
    TooMany { field: &'static str },
    /// A digest is not the canonical lowercase SHA-256 representation.
    #[error("{field} must be a lowercase SHA-256 hex digest")]
    InvalidDigest { field: &'static str },
    /// A stored digest no longer matches the canonical shape bytes.
    #[error("{field} digest does not match the canonical shape")]
    DigestMismatch { field: &'static str },
    /// A numeric value is outside its admitted range.
    #[error("{field} is out of range")]
    OutOfRange { field: &'static str },
    /// A temporal interval is inverted.
    #[error("{field} has an invalid temporal interval")]
    InvertedInterval { field: &'static str },
    /// A record scope does not match the requested scope.
    #[error("{field} scope does not match the requested scope")]
    ScopeMismatch { field: &'static str },
    /// A record fence is not compatible with the requested fence.
    #[error("{field} fence is not compatible with the requested fence")]
    FenceMismatch { field: &'static str },
    /// A record task binding does not match the requested task.
    #[error("{field} task does not match the requested task")]
    TaskMismatch { field: &'static str },
    /// A member or identity appears more than once where exactly one is required.
    #[error("{field} contains a duplicate entry")]
    Duplicate { field: &'static str },
    /// A record references itself as its own predecessor or lineage.
    #[error("{field} references itself")]
    SelfReference { field: &'static str },
    /// A reference names an identity that is not admitted by the manifest.
    #[error("{field} references an unknown identity")]
    MissingReference { field: &'static str },
    /// A claim or handle is outside the admitted reference manifest.
    #[error("{field} is outside the admitted manifest")]
    OutsideManifest { field: &'static str },
    /// Named fields combine into a state the contract forbids.
    #[error("{field} holds an impossible combination")]
    ImpossibleCombination { field: &'static str },
    /// Enumerated members and omissions do not add up to the denominator.
    #[error("{field} arithmetic does not reconcile")]
    ArithmeticMismatch { field: &'static str },
    /// A denominator is not complete, finite, or owned.
    #[error("{field} denominator is incomplete")]
    IncompleteDenominator { field: &'static str },
    /// A denominator uses vague or unbounded wording.
    #[error("{field} denominator is vague or unbounded")]
    VagueDenominator { field: &'static str },
    /// A claimed grade, ceiling, or assertability exceeds its bound.
    #[error("{field} exceeds its ceiling")]
    CeilingViolation { field: &'static str },
    /// A query, scope, fence, or snapshot changed after the claim was frozen.
    #[error("{field} context changed after freezing")]
    StaleContext { field: &'static str },
    /// A contract shape could not be canonicalized.
    #[error("cannot canonicalize contract shape")]
    Canonicalization,
}

/// Validates bounded human-supplied text without ever echoing the value.
pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::Blank { field });
    }
    if value.chars().any(char::is_control) {
        return Err(ContractError::ControlCharacter { field });
    }
    Ok(())
}

/// Validates text that additionally carries an explicit character ceiling.
pub(crate) fn validate_bounded_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), ContractError> {
    validate_text(value, field)?;
    if value.chars().count() > max {
        return Err(ContractError::TooLong { field });
    }
    Ok(())
}

/// Validates that a value is the canonical lowercase SHA-256 hex form.
pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ContractError::InvalidDigest { field });
    }
    Ok(())
}

/// Validates a frozen shape digest against its recomputed canonical bytes.
pub(crate) fn check_frozen(
    digest: &str,
    computed: &str,
    field: &'static str,
) -> Result<(), ContractError> {
    validate_digest(digest, field)?;
    if digest != computed {
        return Err(ContractError::DigestMismatch { field });
    }
    Ok(())
}

/// Returns deterministic canonical JSON bytes for any serializable shape.
pub(crate) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    canonical_json_bytes(value).map_err(|_| ContractError::Canonicalization)
}

/// Returns the SHA-256 hex digest of the canonical JSON bytes of a shape.
pub(crate) fn shape_digest<T: Serialize>(value: &T) -> Result<String, ContractError> {
    let bytes = canonical_bytes(value)?;
    Ok(sha256_hex(&bytes))
}
