//! Deterministic, candidate-only claim grounding for the Dreamer handoff.
//!
//! This cell consumes the complete A03 v2 input context and binds only explicit
//! proposed handles to typed assertions already present in the frozen manifest.
//! It has no retrieval, model, clock, I/O, state, or truth-promotion surface.
//!
//! It also owns the single production construction site of the A-14b -> A-05
//! grounding validation carrier (`validation_bridge`), binding its grounded
//! output to independently supplied A-05 data under the frozen carrier
//! contract. It issues no receipt and runs no A-05 semantic gate.

#![forbid(unsafe_code)]

mod evidence;
pub mod grounding;
mod precision;
pub mod validation_bridge;

pub use grounding::{
    Cancellation, GroundingControls, GroundingRequest, ground_draft, ground_draft_with_controls,
};
pub use validation_bridge::{
    GroundingValidationRequest, ValidationAttachment, ground_for_validation,
};
