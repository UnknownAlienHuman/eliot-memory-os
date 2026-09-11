//! Errors kept outside A32's two successful outcome arms.

use eliot_learning_contracts::LearningContractError;
use thiserror::Error;

/// A bounded failure of pure learning derivation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LearningDeltaError {
    /// A canonical A32 contract rejected its shape.
    #[error("learning contract rejected input: {0}")]
    Contract(#[from] LearningContractError),
    /// An evidence record did not bind to the exact attempt and fence.
    #[error("evidence binding is invalid: {field}")]
    EvidenceBinding { field: &'static str },
    /// A semantic evidence dimension is incomplete or incompatible.
    #[error("evidence is insufficient: {field}")]
    InsufficientEvidence { field: &'static str },
    /// A provider/tool/self-report cannot establish semantic outcome evidence.
    #[error("evidence kind cannot establish a semantic outcome")]
    NonSemanticEvidence,
    /// The current view cannot prove the requested before value.
    #[error("exact current before value is unavailable: {field}")]
    BeforeValueUnavailable { field: &'static str },
    /// A protected owner surface was targeted by the candidate.
    #[error("protected surface cannot be changed")]
    ProtectedSurface,
    /// The attempt is outside the consequential learning boundary.
    #[error("attempt is non-consequential")]
    NonConsequential,
    /// Cancellation happened before a semantic result existed.
    #[error("attempt was cancelled")]
    Cancelled,
    /// The explicit work/output bound was reached.
    #[error("derivation exceeded its declared bound")]
    BoundedOut,
    /// The caller supplied a malformed or conflicting input.
    #[error("attempt input is malformed or conflicted: {field}")]
    InvalidInput { field: &'static str },
    /// Missing semantic evaluator evidence cannot become `NoChange`.
    #[error("independent evaluator evidence is required")]
    MissingEvaluator,
    /// A repeat has no allowed controlled-retry reason.
    #[error("materially equivalent retry requires an allowed reason")]
    EquivalentRetryRequiresReason,
    /// A prior attempt's effect is unknown, so blind retry is unsafe.
    #[error("prior equivalent attempt has unknown effect")]
    UnknownPriorEffect,
    /// The proposed no-change predicate is not established by its evidence.
    #[error("no-change predicate is not affirmatively established")]
    InvalidNoChangePredicate,
    /// A checked input bound was exceeded.
    #[error("{field} exceeds derivation policy bound")]
    Bound { field: &'static str },
}
