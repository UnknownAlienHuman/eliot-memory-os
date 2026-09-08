//! Pure post-admission semantic classification candidate owner (A-21).
//!
//! The implementation is deterministic and candidate-only.
//!
//! Cell `smart.dreamer.classification`, order 21. Callers provide an already
//! accepted [`eliot_dreamer_contracts::CurationAcceptanceCtx`] and the frozen
//! input, policy, grade bindings and explicit runtime observations. The
//! selector returns only a reversible candidate or an explicit abstention;
//! it performs no retrieval, promotion, persistence or canonical mutation.

#![forbid(unsafe_code)]

mod evidence;
mod policy;
mod result;
mod selection;

pub use evidence::{EvidenceQuality, EvidenceTrace, grade_name, retained_source_set};
pub use policy::{BudgetReceipt, ClassificationPolicy, EvidenceGradeBinding, grade_binding_digest};
pub use result::{
    ClassificationConflict, ClassificationDisposition, ClassificationResult, classify,
};
pub use selection::{AlternativeTrace, CriterionResolution, SelectionKind, SelectionReport};
