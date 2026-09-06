//! Shared closed-world error for the provider-neutral Dreamer contract hub.
//! Cell `smart.dreamer.contracts`. Every validation failure in this crate maps
//! to this single error so handler/status bridges can switch on a closed set
//! without string matching. No I/O, no state, no provider surface.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Saturates hostile lengths at [`i64::MAX`] for [`ContractViolation::OutOfBounds`].
#[must_use]
pub fn len_i64(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

/// Rejects blank, over-long, or control-character text against an exact bound.
pub fn check_text(value: &str, field: &'static str, max: usize) -> Result<(), ContractViolation> {
    if value.trim().is_empty() {
        return Err(ContractViolation::MissingField(field));
    }
    if value.len() > max {
        return Err(ContractViolation::OutOfBounds {
            field,
            min: 1,
            max: len_i64(max),
            got: len_i64(value.len()),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ContractViolation::Malformed {
            field,
            reason: "must not contain control characters".to_owned(),
        });
    }
    Ok(())
}

pub fn is_hex64_lower(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn check_vec_bound(
    len: usize,
    cap: usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    if len > cap {
        return Err(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: len_i64(cap),
            got: len_i64(len),
        });
    }
    Ok(())
}

pub fn check_fence(fence: &eliot_contracts::StateFence) -> Result<(), ContractViolation> {
    fence
        .validate()
        .map_err(|err| ContractViolation::BindingMismatch {
            field: "state_fence",
            reason: err.to_string(),
        })
}

/// Compares string sets order-insensitively (callers reject duplicates at ingress).
#[must_use]
pub fn sorted_set_eq(left: &[String], right: &[String]) -> bool {
    let mut ordered_left = left.to_vec();
    ordered_left.sort();
    let mut ordered_right = right.to_vec();
    ordered_right.sort();
    ordered_left == ordered_right
}

/// Closed validation failure for any Dreamer contract shape in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ContractViolation {
    /// A closed enum received an unknown wire spelling.
    #[error("unknown variant for {field}: {value}")]
    UnknownVariant {
        /// Closed field name (e.g. `job_class`, `wire_kind`, `family`).
        field: &'static str,
        /// Rejected wire spelling.
        value: String,
    },
    /// A required field is missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// A value is outside its exact permitted bound.
    #[error("{field} out of bounds: got {got}, permitted {min}..={max}")]
    OutOfBounds {
        /// Field name.
        field: &'static str,
        /// Inclusive lower bound.
        min: i64,
        /// Inclusive upper bound.
        max: i64,
        /// Observed value.
        got: i64,
    },
    /// A protected identity/ordering/receipt/completeness/terminal field used
    /// an implicit default instead of an explicit value.
    #[error("protected field must be explicit, not defaulted: {0}")]
    ImplicitDefault(&'static str),
    /// Wrapper/identity/binding mismatch (source, manifest, scope, fence,
    /// receipt digest, validator, job, draft, bundle).
    #[error("binding mismatch on {field}: {reason}")]
    BindingMismatch {
        /// Binding name.
        field: &'static str,
        /// Exact reason.
        reason: String,
    },
    /// Budget exhausted, unknown-as-unlimited, cross-subsidy, or
    /// class-ceiling violation.
    #[error("budget violation on {dimension}: {reason}")]
    Budget {
        /// Independent budget dimension.
        dimension: &'static str,
        /// Exact reason.
        reason: String,
    },
    /// Cross-stage decode attempt (raw/structured/grounded/validated/candidate).
    #[error("cross-stage decode rejected: {0}")]
    CrossStage(&'static str),
    /// Wrong curation kind/payload pairing or trial-decoding routing attempt.
    #[error("kind/payload mismatch: {0}")]
    KindPayload(String),
    /// Registry registration conflict (duplicate, overlap, changed descriptor).
    #[error("registry conflict: {0}")]
    Registry(String),
    /// Screen reference cannot enable dispatch.
    #[error("screen ineligible: {0}")]
    ScreenIneligible(String),
    /// Preservation dimension failed/unknown and cannot be averaged away.
    #[error("preservation failure: {0}")]
    Preservation(String),
    /// Candidate carries admitted/current/effect/delivery/use/outcome/promotion/Finish evidence.
    #[error("forbidden candidate carry: {0}")]
    ForbiddenCarry(String),
    /// Malformed or hostile input rejected with a bound (never panics).
    #[error("malformed input for {field}: {reason}")]
    Malformed {
        /// Field name.
        field: &'static str,
        /// Exact reason.
        reason: String,
    },
}
