//! Stable local errors for the projection boundary.

use eliot_context_contracts::{ContextError, DecisionContextIncomplete};
use thiserror::Error;

/// Failure while projecting an admitted set into the canonical A-15 view.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AssemblyError {
    /// An A-15 contract rejected the supplied value.
    #[error("context contract rejected assembly: {0}")]
    Contract(#[from] ContextError),
    /// An input or measured output exceeded this package's bounded workset.
    #[error("assembly field exceeds its bound: {0}")]
    Bounds(&'static str),
    /// The measurement did not describe the exact canonical rendered payload.
    #[error("measurement does not bind to the canonical rendered payload: {0}")]
    MeasurementMismatch(&'static str),
    /// The upstream Safety Floor is incomplete and remains explicit.
    #[error("admitted context is incomplete")]
    Incomplete(Box<DecisionContextIncomplete>),
    /// Quality evidence cannot support a complete projection.
    ///
    /// Both halves are retained and neither replaces the other: the card is the
    /// complete twelve-dimension accounting, including every failed, unknown,
    /// degraded and not-applicable result, and the refusal is the typed
    /// operation-scoped answer - which operation was requested, whether it was
    /// blocked by a dimension or by an unresolved applicability input, and the
    /// exact blocking results with the evidence each still lacks. A consumer
    /// that only saw the card would have to re-derive the refusal; a consumer
    /// that only saw the refusal would lose the dimensions that did not block.
    #[error("quality evidence cannot support a complete projection")]
    QualityIncomplete(
        Box<eliot_context_contracts::QualityScorecard>,
        Box<eliot_context_contracts::QualityRefusal>,
    ),
}
