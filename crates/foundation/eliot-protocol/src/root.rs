#![forbid(unsafe_code)]

#[allow(
    dead_code,
    deprecated,
    reason = "the v1 protocol implementation remains a temporary public compatibility surface"
)]
#[path = "lib.rs"]
mod protocol_v1;

pub use protocol_v1::*;

pub mod activation_resolution_v1;

mod activation_resolution;
pub use activation_resolution::{
    AGENT_ACTIVATION_CLAIM_WIRE_ID, AGENT_ACTIVATION_CLAIM_WIRE_VERSION, AGENT_ACTIVATION_OWNER_ID,
    AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID, AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION,
    AGENT_ACTIVATION_RESULT_ACK_WIRE_ID, AGENT_ACTIVATION_RESULT_ACK_WIRE_VERSION,
    AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_ID, AGENT_ACTIVATION_RESULT_RECONCILE_WIRE_VERSION,
    AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_ID, AGENT_ACTIVATION_RESULT_SUBMIT_WIRE_VERSION,
    AgentActivationCandidateCoverage, AgentActivationClaimRequest,
    AgentActivationDependencyObservation, AgentActivationKernelOwnerReadback,
    AgentActivationOwnerEvidence, AgentActivationOwnerReadback,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolvedBinding, AgentActivationResultAck, AgentActivationResultAckOutcome,
    AgentActivationResultReconcile, AgentActivationResultSubmit, AgentActivationRetryDirective,
    AgentActivationSelectionDirective, MAX_AGENT_ACTIVATION_CANDIDATES, binding_digest,
    decode_agent_activation_result_submit,
};

mod invalid_ticket;
pub use invalid_ticket::{
    AGENT_ACTIVATION_INVALID_TICKET_WIRE_ID, AGENT_ACTIVATION_INVALID_TICKET_WIRE_VERSION,
    AgentActivationInvalidTicket, MAX_INVALID_TICKET_BYTES, UNKNOWN_INVALID_TICKET_ID,
};

mod host_event_ingest;
pub use host_event_ingest::{
    HOST_EVENT_INGEST_RECORD_WIRE_ID, HOST_EVENT_INGEST_RECORD_WIRE_VERSION,
    HOST_EVENT_STREAM_CURSOR_WIRE_ID, HOST_EVENT_STREAM_CURSOR_WIRE_VERSION,
    HostEventIngestDispositionWire, HostEventIngestRecordWire, HostEventRedactionReceiptWire,
    HostEventStreamCursorWire, MAX_HOST_EVENT_INGEST_TEXT_BYTES, MAX_HOST_EVENT_REDACTED_CLASSES,
    MAX_HOST_EVENT_STREAM_ID_BYTES,
};
