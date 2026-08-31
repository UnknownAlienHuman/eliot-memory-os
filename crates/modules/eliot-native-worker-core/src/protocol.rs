use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::{AttemptId, AuthorizedEffect, ProposedEffect};
use eliot_contracts::{AuthorityEpoch, StateFence};
use eliot_process::{CancellationStatus, ProcessLifecycle, ProcessStartReceipt};
use eliot_receipts::ReceiptDisposition;
use eliot_runtime_contracts::ServiceProcessState;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::WorkerError;

/// Stable version of A-13's language-neutral native-worker protocol.
pub const PROTOCOL_VERSION: &str = "eliot-native-worker/v2";
/// The only encoding profile admitted by the first native-worker contract.
pub const JSON_ENCODING_PROFILE: &str = "json-v1";

/// Lifecycle owned by the native-worker protocol, not by the process executor.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkerLifecycle {
    Created,
    Starting,
    Ready,
    Running,
    Quiescing,
    Cancelling,
    Cancelled,
    UnknownOutcome,
    Reconciled,
    Stopped,
}

impl WorkerLifecycle {
    pub(crate) const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created | Self::Stopped, Self::Starting)
                | (
                    Self::Starting,
                    Self::Ready | Self::UnknownOutcome | Self::Stopped
                )
                | (
                    Self::Ready,
                    Self::Running
                        | Self::Quiescing
                        | Self::Cancelling
                        | Self::UnknownOutcome
                        | Self::Stopped
                )
                | (
                    Self::Running,
                    Self::Quiescing | Self::Cancelling | Self::UnknownOutcome | Self::Stopped
                )
                | (
                    Self::Quiescing | Self::Cancelling,
                    Self::Cancelled | Self::UnknownOutcome | Self::Stopped
                )
                | (Self::UnknownOutcome, Self::Reconciled | Self::Stopped)
                | (Self::Reconciled, Self::Ready | Self::Stopped)
        )
    }

    /// Projects the protocol lifecycle onto the shared process-state axis.
    #[must_use]
    pub const fn service_state(self) -> ServiceProcessState {
        match self {
            Self::Created | Self::Cancelled | Self::Stopped => ServiceProcessState::Stopped,
            Self::Starting => ServiceProcessState::Starting,
            Self::Ready | Self::Running | Self::Reconciled => ServiceProcessState::Ready,
            Self::Quiescing | Self::Cancelling => ServiceProcessState::Quiescing,
            Self::UnknownOutcome => ServiceProcessState::Failed,
        }
    }
}

/// Client half of the native-worker handshake.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHello {
    pub protocol_version: String,
    pub encoding_profile: String,
    pub connection_id: String,
    pub request_id: String,
    pub trace_context: BTreeMap<String, String>,
    pub deadline_unix_ms: u64,
    pub artifact_manifest_digest: String,
    pub launch_nonce: String,
    pub worker_generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub route_ref: String,
    pub requested_capabilities: BTreeSet<String>,
}

impl WorkerHello {
    pub(crate) fn validate(&self) -> Result<(), WorkerError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(WorkerError::UnsupportedVersion);
        }
        if self.encoding_profile != JSON_ENCODING_PROFILE {
            return Err(WorkerError::UnsupportedEncoding);
        }
        for (field, value) in [
            ("connection_id", &self.connection_id),
            ("request_id", &self.request_id),
            ("artifact_manifest_digest", &self.artifact_manifest_digest),
            ("launch_nonce", &self.launch_nonce),
            ("route_ref", &self.route_ref),
        ] {
            if value.trim().is_empty() {
                return Err(WorkerError::InvalidHandshake(field));
            }
        }
        if self.worker_generation == 0
            || self.deadline_unix_ms == 0
            || self.requested_capabilities.is_empty()
            || self
                .requested_capabilities
                .iter()
                .any(|capability| capability.trim().is_empty())
            || self
                .trace_context
                .iter()
                .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
        {
            return Err(WorkerError::InvalidHandshake("bounded_fields"));
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidHandshake("state_fence"))?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(WorkerError::InvalidHandshake("epoch_fence"));
        }
        Ok(())
    }
}

/// Server half returned only after admission and the P-03 start receipt agree.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReady {
    pub protocol_version: String,
    pub encoding_profile: String,
    pub connection_id: String,
    pub request_id: String,
    pub admission_revision: String,
    pub stream_id: String,
    pub process_start_receipt: ProcessStartReceipt,
    pub ready_event: WorkerEventEnvelope,
}

/// A public request is only a proposal until the injected admission port accepts it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub attempt_id: AttemptId,
    pub capability: String,
    pub payload: BTreeMap<String, String>,
    pub proposed_effect: Option<ProposedEffect>,
}

impl WorkerRequest {
    pub(crate) fn validate_shape(&self) -> Result<(), WorkerError> {
        if self.capability.trim().is_empty() {
            return Err(WorkerError::InvalidRequest("capability"));
        }
        if self.payload.len() > 128 {
            return Err(WorkerError::InvalidRequest("payload"));
        }
        if let Some(effect) = &self.proposed_effect
            && effect.attempt_id != self.attempt_id
        {
            return Err(WorkerError::InvalidRequest("effect_attempt"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub attempt_id: AttemptId,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRequest {
    pub checkpoint_ref: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconnectRequest {
    pub previous_connection_id: String,
    pub new_connection_id: String,
    pub replay_after_sequence: u64,
}

/// Explicit cursor phases; transport receipt cannot impersonate application.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AckPhase {
    Received,
    Durable,
    Normalized,
    Applied,
    Rejected,
    Unknown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventAckReceipt {
    pub stream_id: String,
    pub event_id: String,
    pub sequence: u64,
    pub producer_generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub phase: AckPhase,
    pub acknowledged_at_unix_ms: u64,
}

/// Native worker frame. Every request carries the complete EBP correlation/fence context.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerFrame {
    pub protocol_version: String,
    pub encoding_profile: String,
    pub connection_id: String,
    pub request_id: String,
    pub trace_context: BTreeMap<String, String>,
    pub deadline_unix_ms: u64,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub lease_id: String,
    pub admission_revision: String,
    pub producer_generation: u64,
    pub body: WorkerFrameBody,
}

impl WorkerFrame {
    pub(crate) fn validate_shape(&self) -> Result<(), WorkerError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(WorkerError::UnsupportedVersion);
        }
        if self.encoding_profile != JSON_ENCODING_PROFILE {
            return Err(WorkerError::UnsupportedEncoding);
        }
        for (field, value) in [
            ("connection_id", &self.connection_id),
            ("request_id", &self.request_id),
            ("lease_id", &self.lease_id),
            ("admission_revision", &self.admission_revision),
        ] {
            if value.trim().is_empty() {
                return Err(WorkerError::InvalidFrame(field));
            }
        }
        if self.deadline_unix_ms == 0
            || self.producer_generation == 0
            || self
                .trace_context
                .iter()
                .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
        {
            return Err(WorkerError::InvalidFrame("bounded_fields"));
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidFrame("state_fence"))?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(WorkerError::InvalidFrame("epoch_fence"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum WorkerFrameBody {
    Execute(WorkerRequest),
    Cancel(CancelRequest),
    Heartbeat,
    Health,
    Checkpoint(CheckpointRequest),
    Quiesce,
    Reconnect(ReconnectRequest),
    Reconcile,
    Acknowledge(EventAckReceipt),
    Shutdown,
}

/// Delivery class declared independently from payload semantics.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryClass {
    DurableControl,
    DurableObservation,
    BestEffortTelemetry,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum WorkerEventPayload {
    Ready,
    Accepted {
        attempt_id: AttemptId,
    },
    CandidateOnly {
        proposal: Box<ProposedEffect>,
        authorized_effect: Box<AuthorizedEffect>,
    },
    Heartbeat,
    Health {
        state: ServiceProcessState,
    },
    Checkpoint {
        checkpoint_ref: String,
    },
    Quiescing,
    Cancellation {
        status: CancellationStatus,
        reason: String,
    },
    UnknownOutcome,
    Reconciled {
        process_lifecycle: ProcessLifecycle,
    },
    Reconnected {
        previous_connection_id: String,
        new_connection_id: String,
    },
    Shutdown,
}

/// Exact event content handed to the durable replay owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEventDraft {
    stream_id: String,
    producer_id: String,
    producer_generation: u64,
    authority_epoch: AuthorityEpoch,
    request_id: String,
    causal_predecessor_refs: Vec<String>,
    delivery_class: DeliveryClass,
    ack_required: bool,
    payload_type: String,
    payload: WorkerEventPayload,
    disposition: ReceiptDisposition,
    state_fence: StateFence,
    trace_context: BTreeMap<String, String>,
}

impl WorkerEventDraft {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        stream_id: String,
        producer_id: String,
        producer_generation: u64,
        authority_epoch: AuthorityEpoch,
        request_id: String,
        causal_predecessor_refs: Vec<String>,
        delivery_class: DeliveryClass,
        ack_required: bool,
        payload_type: impl Into<String>,
        payload: WorkerEventPayload,
        disposition: ReceiptDisposition,
        state_fence: StateFence,
        trace_context: BTreeMap<String, String>,
    ) -> Self {
        Self {
            stream_id,
            producer_id,
            producer_generation,
            authority_epoch,
            request_id,
            causal_predecessor_refs,
            delivery_class,
            ack_required,
            payload_type: payload_type.into(),
            payload,
            disposition,
            state_fence,
            trace_context,
        }
    }

    #[must_use]
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Consumes the exact draft so a durable port can assign identity and sequence only.
    pub fn into_envelope(
        self,
        event_id: impl Into<String>,
        sequence: u64,
    ) -> Result<WorkerEventEnvelope, WorkerError> {
        let event_id = event_id.into();
        if event_id.trim().is_empty() || sequence == 0 {
            return Err(WorkerError::ReplayContract("event_identity"));
        }
        Ok(WorkerEventEnvelope {
            stream_id: self.stream_id,
            producer_id: self.producer_id,
            producer_generation: self.producer_generation,
            authority_epoch: self.authority_epoch,
            event_id,
            sequence,
            request_id: self.request_id,
            causal_predecessor_refs: self.causal_predecessor_refs,
            delivery_class: self.delivery_class,
            ack_required: self.ack_required,
            payload_type: self.payload_type,
            payload: self.payload,
            disposition: self.disposition,
            state_fence: self.state_fence,
            trace_context: self.trace_context,
        })
    }
}

/// Durable/control event envelope returned by the injected replay owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEventEnvelope {
    pub stream_id: String,
    pub producer_id: String,
    pub producer_generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub event_id: String,
    pub sequence: u64,
    pub request_id: String,
    pub causal_predecessor_refs: Vec<String>,
    pub delivery_class: DeliveryClass,
    pub ack_required: bool,
    pub payload_type: String,
    pub payload: WorkerEventPayload,
    pub disposition: ReceiptDisposition,
    pub state_fence: StateFence,
    pub trace_context: BTreeMap<String, String>,
}

/// Restart recovery result. Events are the durable identities returned by the replay owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRecovery {
    pub connection_id: String,
    pub lifecycle: WorkerLifecycle,
    pub replayed_events: Vec<WorkerEventEnvelope>,
}
