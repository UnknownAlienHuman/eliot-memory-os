#![forbid(unsafe_code)]

#[allow(
    dead_code,
    deprecated,
    reason = "the v1 protocol implementation remains a temporary public compatibility surface"
)]
#[path = "lib.rs"]
mod protocol_v1;

pub use protocol_v1::*;

mod activation_resolution;
pub use activation_resolution::{
    AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID, AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION,
    AgentActivationCandidateCoverage, AgentActivationResolutionDisposition,
    AgentActivationResolutionResult, AgentActivationResolvedBinding, AgentActivationRetryDirective,
    AgentActivationSelectionDirective, MAX_AGENT_ACTIVATION_CANDIDATES,
};
