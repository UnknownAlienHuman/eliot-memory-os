//! ControlBoard-consumable, zero-model projection for Swarm model and attempt
//! control.
//!
//! This module composes immutable A-02 catalogue, Human preference, exact
//! model-selection receipts, and `AgentAttempt` telemetry into one bounded read
//! model. It performs no provider call, process launch, route admission, retry,
//! task transition, or finish decision. A-08 remains the Human surface owner.

mod compile;
pub mod diversity;
mod types;

pub use compile::compile_swarm_controlboard_projection;
pub use diversity::{
    DegradedDiversity, DiversityDecision, DiversityDimension, DiversityError, DiversityOutcome,
    DiversityRequirement, decide_diversity, decide_swarm_diversity,
    validate_no_secret_or_fixed_input, validate_one_primary_per_host,
};
pub use types::*;

#[cfg(test)]
mod tests;
