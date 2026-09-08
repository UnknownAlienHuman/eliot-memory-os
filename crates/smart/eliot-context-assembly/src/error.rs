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
    #[error("quality evidence cannot support a complete projection")]
    QualityIncomplete(Box<eliot_context_contracts::QualityScorecard>),
}
