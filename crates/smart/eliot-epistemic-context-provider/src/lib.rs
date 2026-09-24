//! Epistemic Context provider contribution (#223, review repair).
//!
//! The provider cell lives in [`context_projection`]; this root only
//! re-exports the cell surface so provider consumers keep one vocabulary.

#![forbid(unsafe_code)]

mod context_projection;

pub use context_projection::{
    ContributionError, EpistemicContextContribution, FREEZE_ID, PROVIDER_LABEL,
};
