//! Deterministic, candidate-only claim grounding for the Dreamer handoff.
//!
//! This cell consumes the complete A03 v2 input context and binds only explicit
//! proposed handles to typed assertions already present in the frozen manifest.
//! It has no retrieval, model, clock, I/O, state, or truth-promotion surface.

#![forbid(unsafe_code)]

mod evidence;
pub mod grounding;
mod precision;

pub use grounding::{
    Cancellation, GroundingControls, GroundingRequest, ground_draft, ground_draft_with_controls,
};
