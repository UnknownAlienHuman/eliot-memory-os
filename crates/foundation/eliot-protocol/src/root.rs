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
    AGENT_ACTIVATION_RESULT_ACK_WIRE_ID, AGENT_ACTIVATION_RESULT_ACK_WIRE_VERSION,
    AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_ID, AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_VERSION,
    AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_ID, AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_VERSION,
    AgentActivationCandidateCoverage, AgentActivationResolutionDisposition,
    AgentActivationResolutionResult, AgentActivationResolvedBinding, AgentActivationResultAck,
    AgentActivationResultAckOutcome, AgentActivationResultReconcile, AgentActivationResultSubmit,
    AgentActivationRetryDirective, AgentActivationSelectionDirective,
    MAX_AGENT_ACTIVATION_CANDIDATES,
};

mod invalid_ticket;
pub use invalid_ticket::{
    AGENT_ACTIVATION_INVALID_TICKET_WIRE_ID, AGENT_ACTIVATION_INVALID_TICKET_WIRE_VERSION,
    AgentActivationInvalidTicket, MAX_INVALID_TICKET_BYTES, UNKNOWN_INVALID_TICKET_ID,
};
