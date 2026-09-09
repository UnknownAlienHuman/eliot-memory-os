//! Deterministic, candidate-only `FailureFingerprint` synthesis.
//!
//! The handler consumes the complete A03 Failure closure and emits one sealed
//! candidate artifact. It never performs I/O, calls a provider, reads a clock,
//! mutates memory, blocks an action, or promotes causal authority.

#![forbid(unsafe_code)]

mod assessment;
mod policy;
mod result;

pub use assessment::{
    ApplicabilityAssessment, CausalLimits, FailureAssessment, FailureCountSummary,
    OutcomeAssessment, TriggerAssessment,
};
pub use eliot_dreamer_contracts::FailureDisposition;
pub use policy::FailurePolicy;
pub use result::{
    FailureHandlerDecision, FailureResult, handler_port, propose_failure_fingerprint,
};

/// Stable registry identity for this handler.
pub const HANDLER_ID: &str = "eliot-dreamer-failure";
