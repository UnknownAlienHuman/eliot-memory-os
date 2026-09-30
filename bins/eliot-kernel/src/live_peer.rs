//! Kernel-side typed live-peer delta payload (`I10.18`).
//!
//! A [`LivePeerMessagePayload`] carries only a bounded, deduplicable delta:
//! sender/recipient attempt/work-item references, the frozen plan/wave
//! revision, one permitted delta kind, evidence/artifact handles, the
//! requested reaction, urgency, expiry, and the next-admissible-boundary
//! delivery policy. It is a mailbox payload on top of the mailbox work, not
//! a new chat channel: this module opens no channel, transport, or send
//! path.
//!
//! Sender semantics are fixed by construction. The payload is pure data, so
//! a sender waits only for durable admission of the admitted record. There
//! is no acknowledgement, response, or plan-revision wait here, and no code
//! path interrupts the current model/tool step.
//!
//! Deduplication compares the recorded `dedup_key` content at admission; this
//! module computes no digests. The Context Compiler admission gate and the
//! four delivery profiles arrive in the next slice, which stitches this
//! payload in (caller: `STITCH`).
//!
//! Urgent kinds create no truth, authority, completion, plan revision, or
//! write-scope expansion. That holds by construction: this module imports no
//! store, authority, effect, or scheduler surface and contains no code path
//! that could create any of those outcomes. Identity, principals,
//! timestamps, ordering, provenance, privacy/disclosure, State Fence, and
//! delivery receipts stay on the common envelope and are not duplicated
//! here.

use eliot_contracts::{ContractError, PeerBoardKind, canonical_json_bytes};
use eliot_protocol::ProtocolError;
use serde::{Deserialize, Serialize};

/// Largest admitted canonical payload encoding, in bytes.
///
/// Mirrors the contract-owner bound
/// (`eliot-agent-contracts::MAX_LIVE_PEER_PAYLOAD_BYTES`) so the kernel
/// budget check stays identical without adding a dependency edge.
pub const MAX_LIVE_PEER_PAYLOAD_BYTES: usize = 65_536;

/// Largest admitted evidence/artifact handle fan-out per payload.
///
/// Mirrors the contract-owner bound
/// (`eliot-agent-contracts::MAX_LIVE_PEER_REFERENCES`) so the kernel fan-out
/// check stays identical without adding a dependency edge.
pub const MAX_LIVE_PEER_REFERENCES: usize = 16;

/// One permitted live-peer delta kind (`I10.18`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivePeerDeltaKind {
    RelevantFinding,
    AssumptionInvalidated,
    DependencyDiscovered,
    PlanContradiction,
    Obstacle,
    AbandonedDeadEnd,
}

/// Reaction requested at the next admissible boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivePeerRequestedReaction {
    Inform,
    Revalidate,
    Reply,
    PauseDependentEffect,
}

/// Delivery timing. Urgency is never an interrupt guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivePeerUrgency {
    Normal,
    BeforeNextDependentEffect,
}

/// When an admitted delta may be observed. Only the next admissible boundary
/// exists; route delivery profiles belong to the next slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivePeerDeliveryPolicy {
    NextAdmissibleBoundary,
}

/// One explicit recipient: an assigned attempt or a work item, never an
/// implicit semantic subscription. Exactly one side is set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivePeerRecipient {
    pub attempt: Option<String>,
    pub work_item: Option<String>,
}

/// One evidence/artifact expansion handle. The handle kind reuses the closed
/// `I10.18` blackboard vocabulary; the handle carries identity only, never
/// payload or private text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivePeerEvidenceHandle {
    pub kind: PeerBoardKind,
    pub id: String,
    pub revision: String,
}

/// Bounded, deduplicable live-peer delta. Message identity, principals,
/// timestamps, ordering, provenance, privacy/disclosure, State Fence, and
/// lifecycle stay on the common mailbox envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivePeerMessagePayload {
    pub sender_attempt: String,
    pub sender_work_item: String,
    pub recipients: Vec<LivePeerRecipient>,
    pub plan_revision: String,
    pub wave_revision: String,
    pub kind: LivePeerDeltaKind,
    pub concise_delta: String,
    pub evidence_handles: Vec<LivePeerEvidenceHandle>,
    pub requested_reaction: LivePeerRequestedReaction,
    pub urgency: LivePeerUrgency,
    pub dedup_key: String,
    pub expires_at: Option<u64>,
    pub delivery_policy: LivePeerDeliveryPolicy,
}

/// Rejects blank or control-bearing text with the foundation typed failure.
fn live_peer_text(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::Blank { field });
    }
    if value.chars().any(char::is_control) {
        return Err(ContractError::ControlCharacter { field });
    }
    Ok(())
}

impl LivePeerMessagePayload {
    /// Validates payload bounds, explicit recipients, and handle identity.
    ///
    /// Text rules reuse the foundation contract failures; structural and
    /// budget rules use the protocol typed failures. No digest is computed:
    /// deduplication compares the recorded `dedup_key` content at admission.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        live_peer_text(&self.sender_attempt, "sender_attempt")?;
        live_peer_text(&self.sender_work_item, "sender_work_item")?;
        live_peer_text(&self.plan_revision, "plan_revision")?;
        live_peer_text(&self.wave_revision, "wave_revision")?;
        live_peer_text(&self.concise_delta, "concise_delta")?;
        if self.concise_delta.len() > MAX_LIVE_PEER_PAYLOAD_BYTES {
            return Err(ProtocolError::OversizeFrame {
                actual: self.concise_delta.len(),
                maximum: MAX_LIVE_PEER_PAYLOAD_BYTES,
            });
        }
        live_peer_text(&self.dedup_key, "dedup_key")?;
        if self.recipients.is_empty() {
            return Err(ProtocolError::InvalidField {
                field: "recipients",
                reason: "at least one explicit recipient is required",
            });
        }
        for recipient in &self.recipients {
            let addressed = recipient.attempt.is_some() != recipient.work_item.is_some();
            if !addressed {
                return Err(ProtocolError::InvalidField {
                    field: "recipients",
                    reason: "recipient must address exactly one attempt or work item",
                });
            }
            if let Some(attempt) = &recipient.attempt {
                live_peer_text(attempt, "recipients.attempt")?;
                if attempt == &self.sender_attempt {
                    return Err(ProtocolError::InvalidField {
                        field: "recipients",
                        reason: "sender cannot address itself",
                    });
                }
            }
            if let Some(work_item) = &recipient.work_item {
                live_peer_text(work_item, "recipients.work_item")?;
                if work_item == &self.sender_work_item {
                    return Err(ProtocolError::InvalidField {
                        field: "recipients",
                        reason: "sender cannot address itself",
                    });
                }
            }
        }
        for (index, recipient) in self.recipients.iter().enumerate() {
            if self.recipients[..index].contains(recipient) {
                return Err(ProtocolError::InvalidField {
                    field: "recipients",
                    reason: "duplicate recipient",
                });
            }
        }
        if self.evidence_handles.len() > MAX_LIVE_PEER_REFERENCES {
            return Err(ProtocolError::InvalidField {
                field: "evidence_handles",
                reason: "evidence handle fan-out exceeds the bounded limit",
            });
        }
        for handle in &self.evidence_handles {
            live_peer_text(&handle.id, "evidence_handles.id")?;
            live_peer_text(&handle.revision, "evidence_handles.revision")?;
        }
        let payload_bytes =
            canonical_json_bytes(self).map_err(|_| ProtocolError::InvalidField {
                field: "live_peer_payload",
                reason: "payload is not canonically encodable",
            })?;
        if payload_bytes.len() > MAX_LIVE_PEER_PAYLOAD_BYTES {
            return Err(ProtocolError::OversizeFrame {
                actual: payload_bytes.len(),
                maximum: MAX_LIVE_PEER_PAYLOAD_BYTES,
            });
        }
        Ok(())
    }
}
