//! Store- and transport-neutral ELIOT Bridge Protocol (`EBP/1`) contracts.
//!
//! The existing protocol surface is compiled unchanged through the hidden
//! `protocol_v1` compatibility module and re-exported from the crate root.
//! New typed activation-result semantics live in their own additive module so
//! current consumers remain source-compatible while parent issue #66 migrates.

#![forbid(unsafe_code)]

// Pre-v2 protocol implementation retained unchanged during consumer migration.
#[path = "lib.rs"]
mod protocol_v1;
pub use protocol_v1::*;

mod activation_resolution;
pub use activation_resolution::{
    AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID,
    AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolvedBinding, AgentActivationRetryDirective,
    AgentActivationSelectionDirective, MAX_AGENT_ACTIVATION_CANDIDATES,
};
