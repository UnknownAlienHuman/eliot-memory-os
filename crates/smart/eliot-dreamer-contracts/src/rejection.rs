//! Closed contract-only curation rejection vocabulary.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! [`CurationRejectionCode`] mirrors the eight A-05 `RejectionCode` variants
//! (`eliot-dreamer-candidate-validation/src/error.rs:17-34`) one-to-one with
//! identical `snake_case` wire spellings, so the hub names the same semantic
//! rejection reasons without depending on the A-05 crate. The hub
//! [`ContractViolation`][crate::error::ContractViolation] stays untouched: it
//! reports shape/binding violations, while this vocabulary reports semantic
//! rejection reasons. A typed cross-crate mapping function is deliberately
//! absent: naming the A-05 type would require the forbidden
//! `eliot-dreamer-candidate-validation` dependency, so the exact 1:1
//! correspondence is pinned here by per-variant documentation, the
//! [`CurationRejectionCode::a05_counterpart`] spec pin, and byte-identical
//! wire spellings proven by package-local tests.
//!
//! Exact mapping (hub variant → A-05 variant → wire spelling):
//!
//! | Hub (`CurationRejectionCode`) | A-05 (`RejectionCode`) | Wire |
//! |---|---|---|
//! | `IdentityMismatch` | `IdentityMismatch` | `identity_mismatch` |
//! | `LineageMismatch` | `LineageMismatch` | `lineage_mismatch` |
//! | `UnsupportedPrecision` | `UnsupportedPrecision` | `unsupported_precision` |
//! | `BudgetExceeded` | `BudgetExceeded` | `budget_exceeded` |
//! | `DeadlineExceeded` | `DeadlineExceeded` | `deadline_exceeded` |
//! | `Cancelled` | `Cancelled` | `cancelled` |
//! | `PreservationFailed` | `PreservationFailed` | `preservation_failed` |
//! | `UnsupportedJobShape` | `UnsupportedJobShape` | `unsupported_job_shape` |
//!
//! Unlike enums are never equated: no `PartialEq` or conversion exists
//! between this hub enum and the A-05 enum, and no runtime control flow
//! matches on strings. Owns no I/O and no A-05 dependency.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::closed_wire_enum;

/// Closed semantic reason for retaining a rejected curation candidate.
///
/// Contract-only hub vocabulary mirroring A-05 `RejectionCode` 1:1. Each
/// variant documents its exact A-05 counterpart; wire spellings are
/// byte-identical to the A-05 serde spellings.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CurationRejectionCode {
    /// Job, bundle, draft, task, scope, or fence identities disagree.
    /// Exact counterpart of A-05 `RejectionCode::IdentityMismatch`.
    IdentityMismatch,
    /// A model handle or grounded lineage points outside supplied material.
    /// Exact counterpart of A-05 `RejectionCode::LineageMismatch`.
    LineageMismatch,
    /// Candidate content asks the gate to make an unsupported claim.
    /// Exact counterpart of A-05 `RejectionCode::UnsupportedPrecision`.
    UnsupportedPrecision,
    /// The supplied independent usage cannot authorize this input.
    /// Exact counterpart of A-05 `RejectionCode::BudgetExceeded`.
    BudgetExceeded,
    /// The injected observation is at or beyond the frozen deadline.
    /// Exact counterpart of A-05 `RejectionCode::DeadlineExceeded`.
    DeadlineExceeded,
    /// The caller explicitly cancelled this validation.
    /// Exact counterpart of A-05 `RejectionCode::Cancelled`.
    Cancelled,
    /// One of the seven preservation dimensions is not proven.
    /// Exact counterpart of A-05 `RejectionCode::PreservationFailed`.
    PreservationFailed,
    /// A common job shape is outside the supported contract.
    /// Exact counterpart of A-05 `RejectionCode::UnsupportedJobShape`.
    UnsupportedJobShape,
}

closed_wire_enum!(assoc CurationRejectionCode, field = "curation_rejection", [
    IdentityMismatch => "identity_mismatch",
    LineageMismatch => "lineage_mismatch",
    UnsupportedPrecision => "unsupported_precision",
    BudgetExceeded => "budget_exceeded",
    DeadlineExceeded => "deadline_exceeded",
    Cancelled => "cancelled",
    PreservationFailed => "preservation_failed",
    UnsupportedJobShape => "unsupported_job_shape",
]);

impl CurationRejectionCode {
    /// All eight codes in canonical order.
    pub const ALL: [Self; 8] = [
        Self::IdentityMismatch,
        Self::LineageMismatch,
        Self::UnsupportedPrecision,
        Self::BudgetExceeded,
        Self::DeadlineExceeded,
        Self::Cancelled,
        Self::PreservationFailed,
        Self::UnsupportedJobShape,
    ];

    /// Returns the exact A-05 `RejectionCode` variant this hub code mirrors.
    ///
    /// Spec pin for reviewers, not control flow: unlike enums are never
    /// equated and no runtime branch matches on these strings. A typed
    /// cross-crate function would require the forbidden A-05 dependency.
    #[must_use]
    pub const fn a05_counterpart(self) -> &'static str {
        match self {
            Self::IdentityMismatch => "RejectionCode::IdentityMismatch",
            Self::LineageMismatch => "RejectionCode::LineageMismatch",
            Self::UnsupportedPrecision => "RejectionCode::UnsupportedPrecision",
            Self::BudgetExceeded => "RejectionCode::BudgetExceeded",
            Self::DeadlineExceeded => "RejectionCode::DeadlineExceeded",
            Self::Cancelled => "RejectionCode::Cancelled",
            Self::PreservationFailed => "RejectionCode::PreservationFailed",
            Self::UnsupportedJobShape => "RejectionCode::UnsupportedJobShape",
        }
    }
}
