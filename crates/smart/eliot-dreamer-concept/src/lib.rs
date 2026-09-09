//! Deterministic, candidate-only Concept and Abstraction synthesis.
//!
//! This cell consumes the A03 typed closure and emits one reversible candidate.
//! It has no provider, storage, clock, model, or canonical-state effects.
//!
#![forbid(unsafe_code)]

mod compare;
mod evidence;
mod policy;
mod synthesis;

pub use policy::ConceptPolicy;
pub use synthesis::{ConceptDecision, handler_port, propose_concept_or_abstraction};

/// Stable handler identity for the single `Concept` wire kind.
pub const HANDLER_ID: &str = "eliot-dreamer-concept";
