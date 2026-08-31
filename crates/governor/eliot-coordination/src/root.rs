//! Production Governor coordination contract and owner.
//!
//! The established deterministic state machine remains isolated in `lib.rs`.
//! This crate root exposes the production owner wrapper, which preserves the
//! original serialized projection while adding immutable WorkLease issuance
//! provenance under the same lifecycle owner.

#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod coordination;
mod owner;
mod work_lease_issuance;

pub use coordination::{
    CONTRACT_NAME, CONTRACT_VERSION, ActiveWorkLeaseProjection, AgentHeartbeat, AgentResultDraft,
    AgentResultReceipt, AgentSession, CheckpointReceipt, CoordinationError, CoordinationEvent,
    CoordinationEventDraft, CoordinationEventKind, CoordinationEventReceipt, HeartbeatAck,
    IntegrationCandidateDraft, IntegrationCandidateReceipt, IntegrationLease,
    IntegrationLeaseDecision, IntegrationLeaseRequest, MailboxMessage, MailboxMessageDraft,
    MailboxReceipt, ReassignWorkRequest, RegisterSession, SessionState, WorkCheckpoint, WorkItem,
    WorkLease, WorkLeaseDecision, WorkLeaseRequest, WorkState,
};
pub use owner::CoordinationOwner;
pub use work_lease_issuance::{
    WorkLeaseIssuanceDisposition, WorkLeaseIssuanceError, WorkLeaseIssuanceFailure,
    WorkLeaseIssuanceProvenance, WorkLeaseIssuanceResult,
};
