//! Owner-neutral bounded canonical memory projection and applicability-set contracts (CC-008).
//!
//! The contract cell lives in [`contracts`]; this root only re-exports the
//! cell surface so provider and evaluator consumers keep one vocabulary.

#![forbid(unsafe_code)]

mod contracts;
mod workflow_view;

pub use contracts::*;
pub use workflow_view::{
    MAX_WORKFLOW_ENTRIES, MAX_WORKFLOW_GAPS, WorkflowIdempotency, WorkflowStateView,
};
