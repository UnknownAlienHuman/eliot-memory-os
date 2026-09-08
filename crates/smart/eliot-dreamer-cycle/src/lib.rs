//! Pure bounded one-step Dreamer controller transition.
//!
//! The crate consumes immutable state, a frozen policy and already-observed
//! owner receipts. It emits at most one adjacent candidate revision and inert
//! requests. It performs no scheduling, provider/model call, storage access,
//! authority mutation or task completion.

#![forbid(unsafe_code)]

mod bounds;
mod error;
mod policy;
mod receipt;
mod step;

pub mod contract;

pub use contract::{
    CYCLE_SCHEMA_VERSION, CyclePhase, CyclePolicy, CycleStep, DreamerCycleState, ExpectedArtifact,
    InertOwnerRequest, ObservedOutcome, OutcomeDisposition, PendingRequest, PhasePolicyRule,
    RequestKind, StepDisposition,
};
pub use error::CycleError;
pub use step::{step_dreamer_cycle, step_dreamer_cycle_at};
