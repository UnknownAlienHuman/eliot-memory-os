//! Deterministic, candidate-only claim grounding for the Dreamer handoff.
//!
//! This cell consumes the complete A03 v2 input context and binds only explicit
//! proposed handles to typed assertions already present in the frozen manifest.
//! It has no retrieval, model, clock, I/O, state, or truth-promotion surface.
//!
//! It also owns this crate's single production construction site of the
//! A-14b -> A-05 grounding validation carrier (`validation_bridge`), binding its
//! grounded output to independently supplied A-05 data under the frozen carrier
//! contract. That site is crate-internal, so the public surface of THIS crate
//! cannot bind a carrier from a grounded value that never passed through this
//! crate's grounding entry and ceiling refusal; the carrier type itself is a
//! frozen contracts-crate value whose own `pub` constructor stays reachable from
//! any dependent of `eliot-dreamer-contracts` and is not a path this cell owns.
//! It issues no receipt and runs no A-05 semantic gate.

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
