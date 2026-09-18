use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::{AttemptId, AuthorizedEffect, BudgetEnvelope, ProposedEffect, WorkLeaseId};
use eliot_contracts::{
    DecisionId, EpochId, ResourceGeneration, SessionId, StateFence, TaskId, canonical_json_bytes,
    sha256_hex,
};
use eliot_process::{
    CancellationStatus, OperationId, ProcessLifecycle, ProcessStartReceipt, ResourceLimits,
    SecretRef,
};
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
    pub authority_epoch: EpochId,
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
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
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
    pub authority_epoch: EpochId,
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
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    pub lease_id: WorkLeaseId,
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
            ("admission_revision", &self.admission_revision),
        ] {
            if value.trim().is_empty() {
                return Err(WorkerError::InvalidFrame(field));
            }
        }
        // lease_id carries canonical WorkLeaseId via eliot-agent-api re-export:
        // blank/control/too-long/wrong-domain rejected at Deserialize boundary;
        // binding enforced via == against grant.authority().lease.
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
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
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
    authority_epoch: EpochId,
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
        authority_epoch: EpochId,
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
    pub authority_epoch: EpochId,
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

// ---------------------------------------------------------------------------
// Wave A (issue #872): typed registration / claim / readiness protocol.
//
// One Kernel-admitted native-worker process generation claims exactly one
// Kernel-owned execution unit and proves current readiness before any
// provider work. This section is pure types plus validation: no behavior, no
// stores, no IO, no provider selection, and no credential storage. Credential
// material never appears here; only references (`SecretRef`, digests) cross
// this boundary.
// ---------------------------------------------------------------------------

/// Current supported execution-unit schema version.
///
/// A registration presenting any other version is rejected as unknown; the
/// Kernel never negotiates a schema it does not implement.
pub const EXECUTION_UNIT_SCHEMA_VERSION: u16 = 1;
/// Current revision of the worker-side native-worker claim wire (T9-02).
///
/// Revision 2 carries the executable-binding join (`executable_binding` with
/// the owner-produced executable digest plus M1 currentness inputs).
/// Revision 1 still parses — its join decodes as absent — but can never
/// satisfy [`NativeWorkerClaim::require_executable_binding`].
pub const NATIVE_WORKER_CLAIM_WIRE_VERSION: u16 = 2;
/// Previous claim-wire revision, retained only to reject old-wire claims
/// explicitly at the executable gate instead of promoting them silently.
pub const NATIVE_WORKER_CLAIM_WIRE_VERSION_V1: u16 = 1;
/// Expected wire revision of the owner-produced executable binding (T9-01
/// `NativeWorkerExecutableBinding` v1).
///
/// Carried by value, never imported: this crate must not depend on
/// `eliot-governor`. A binding-wire drift changes the owner digest as well,
/// so this pin fails closed twice.
pub const NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION: u16 = 1;
/// Maximum length of bounded claim/registration text fields, in UTF-8 bytes.
pub const MAX_CLAIM_TEXT_LEN: usize = 1_024;
/// Maximum length of one native-worker operation identity, in UTF-8 bytes.
pub const MAX_OPERATION_IDENTITY_LEN: usize = 256;
/// Maximum entries admitted in one registration invalidation set.
pub const MAX_INVALIDATION_ENTRIES: usize = 64;
/// Maximum credential references admitted in one readiness report.
pub const MAX_CREDENTIAL_REFERENCES: usize = 64;

/// Declares one distinct native-worker operation identity family.
///
/// Each of the nine lifecycle operations (registration, renewal, claim,
/// ready, heartbeat, checkpoint, cancellation, result submission,
/// acknowledgement) carries its own newtype so identities cannot be
/// interchanged across operations. Construction and deserialization both
/// reject blank, control-bearing, and oversized values.
macro_rules! native_operation_id {
    ($name:ident, $label:literal, $error:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a validated operation identity.
            ///
            /// # Errors
            ///
            /// Returns the operation-appropriate [`WorkerError`] when the
            /// value is blank, carries control characters, or exceeds
            /// [`MAX_OPERATION_IDENTITY_LEN`] bytes.
            pub fn new(value: impl Into<String>) -> Result<Self, WorkerError> {
                let value = value.into();
                if value.trim().is_empty()
                    || value.chars().any(char::is_control)
                    || value.len() > MAX_OPERATION_IDENTITY_LEN
                {
                    return Err(WorkerError::$error($label));
                }
                Ok(Self(value))
            }

            /// Returns the stable textual representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = WorkerError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(<D::Error as serde::de::Error>::custom)
            }
        }
    };
}

native_operation_id!(
    NativeRegistrationId,
    "native_registration_id",
    InvalidHandshake
);
native_operation_id!(NativeRenewalId, "native_renewal_id", InvalidHandshake);
native_operation_id!(NativeClaimId, "native_claim_id", InvalidRequest);
native_operation_id!(NativeReadyId, "native_ready_id", InvalidRequest);
native_operation_id!(NativeHeartbeatId, "native_heartbeat_id", InvalidRequest);
native_operation_id!(NativeCheckpointId, "native_checkpoint_id", InvalidRequest);
native_operation_id!(
    NativeCancellationId,
    "native_cancellation_id",
    InvalidRequest
);
native_operation_id!(NativeResultId, "native_result_id", InvalidRequest);
native_operation_id!(NativeAckId, "native_ack_id", InvalidRequest);

/// Returns true when the value is a lowercase SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates bounded registration text, rejecting blank, control-bearing, and
/// oversized values with a handshake error.
fn validate_registration_text(value: &str, field: &'static str) -> Result<(), WorkerError> {
    if value.trim().is_empty()
        || value.chars().any(char::is_control)
        || value.len() > MAX_CLAIM_TEXT_LEN
    {
        return Err(WorkerError::InvalidHandshake(field));
    }
    Ok(())
}

/// Validates bounded claim text, rejecting blank, control-bearing, and
/// oversized values with a request error.
fn validate_claim_text(value: &str, field: &'static str) -> Result<(), WorkerError> {
    if value.trim().is_empty()
        || value.chars().any(char::is_control)
        || value.len() > MAX_CLAIM_TEXT_LEN
    {
        return Err(WorkerError::InvalidRequest(field));
    }
    Ok(())
}

/// Closed native-worker registration binding.
///
/// Binds one installation, one worker artifact/config/protocol generation,
/// one process/start identity, one principal/session, one connection, the
/// current [`EpochId`]/[`StateFence`], the registration lease
/// (identity, expiry, and renewal identity), the supported execution-unit
/// schema version, the resource envelope, and the invalidation set. Kernel
/// admits at most one current registration per worker generation; anything
/// else is stale and fenced, never merged.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerRegistration {
    /// Distinct registration operation identity.
    pub registration_id: NativeRegistrationId,
    /// Installation that owns the worker artifact projection.
    pub installation_id: String,
    /// Lowercase SHA-256 of the exact admitted worker artifact bytes.
    pub worker_artifact_digest: String,
    /// Lowercase SHA-256 of the exact admitted worker configuration bytes.
    pub worker_config_digest: String,
    /// Native-worker protocol version; must equal [`PROTOCOL_VERSION`].
    pub protocol_version: String,
    /// Worker process generation; nonzero and fenced on replacement.
    pub worker_generation: u64,
    /// OS process identity observed at start; PID/name/path alone are never
    /// sufficient without the remaining binding.
    pub process_id: u32,
    /// Handle-bound process start time in Windows 100-nanosecond units.
    pub process_start_100ns: u64,
    /// Lowercase SHA-256 of the exact worker image bytes.
    pub process_image_digest: String,
    /// Principal reference bound by the installation boundary. A reference
    /// only; secret or session material never crosses here.
    pub principal_ref: String,
    /// Semantic session bound by the harness/installation boundary.
    pub session_id: SessionId,
    /// Transport connection carrying this registration.
    pub connection_id: String,
    /// Current authority epoch; must equal `state_fence.authority_epoch`.
    pub authority_epoch: EpochId,
    /// Exact immutable fence paired with the generation and epoch.
    pub state_fence: StateFence,
    /// Registration lease identity; expiry ends authority without renewal.
    pub lease_id: String,
    /// Lease expiry in Unix milliseconds; nonzero.
    pub lease_expires_at_unix_ms: u64,
    /// Renewal operation identity; a renewal is never a silent lease edit.
    pub renewal_id: NativeRenewalId,
    /// Supported execution-unit schema version.
    pub execution_unit_schema_version: u16,
    /// Admitted resource envelope for the worker generation.
    pub resource_limits: ResourceLimits,
    /// Bounded set of superseded identity references invalidated by this
    /// registration.
    pub invalidation_set: BTreeSet<String>,
}

impl NativeWorkerRegistration {
    /// Validates the closed registration shape and every binding it carries.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnsupportedVersion`] for an unknown protocol or
    /// execution-unit schema version, [`WorkerError::InvalidHandshake`] for
    /// any malformed, unbounded, or disagreeing field.
    pub fn validate(&self) -> Result<(), WorkerError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(WorkerError::UnsupportedVersion);
        }
        if self.execution_unit_schema_version != EXECUTION_UNIT_SCHEMA_VERSION {
            return Err(WorkerError::UnsupportedVersion);
        }
        for (digest, field) in [
            (&self.worker_artifact_digest, "worker_artifact_digest"),
            (&self.worker_config_digest, "worker_config_digest"),
            (&self.process_image_digest, "process_image_digest"),
        ] {
            if !is_lowercase_sha256(digest) {
                return Err(WorkerError::InvalidHandshake(field));
            }
        }
        for (text, field) in [
            (&self.installation_id, "installation_id"),
            (&self.principal_ref, "principal_ref"),
            (&self.connection_id, "connection_id"),
            (&self.lease_id, "lease_id"),
        ] {
            validate_registration_text(text, field)?;
        }
        if self.worker_generation == 0
            || self.process_id == 0
            || self.process_start_100ns == 0
            || self.lease_expires_at_unix_ms == 0
        {
            return Err(WorkerError::InvalidHandshake("bounded_fields"));
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidHandshake("state_fence"))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(WorkerError::InvalidHandshake("epoch_fence"));
        }
        if self.resource_limits.wall_timeout_ms() == 0
            || self.resource_limits.stdout_bytes() == 0
            || self.resource_limits.stderr_bytes() == 0
            || matches!(self.resource_limits.cpu_time_ms(), Some(0))
            || matches!(self.resource_limits.memory_bytes(), Some(0))
        {
            return Err(WorkerError::InvalidHandshake("resource_limits"));
        }
        if self.invalidation_set.len() > MAX_INVALIDATION_ENTRIES
            || self
                .invalidation_set
                .iter()
                .any(|entry| validate_registration_text(entry, "invalidation_set").is_err())
        {
            return Err(WorkerError::InvalidHandshake("invalidation_set"));
        }
        Ok(())
    }
}

/// Worker-side projection of the owner-produced executable binding (T9-02).
///
/// Carries the M1 currentness inputs the start path needs for refusal —
/// route, adapter, config, facet, grant revision, replay stream, launch
/// nonce, invocation digest, epoch/generation/fence, and the binding window
/// — plus the opaque owner-produced `NativeWorkerExecutableBinding` v1
/// digest. Field names reuse the T9-01 names where they exist, matching the
/// Kernel-side `eliot-kernel-service` projection field-for-field. This is an
/// identity/epoch/fence/ordering projection only: it carries references and
/// revisions, never task meaning, plan/policy content, effective ceilings,
/// credential or resource values, or Governor composition. The full T9-01
/// record stays with its owner; this side compares the carried digest for
/// equality against the current owner record and refuses any stale join.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerExecutableBinding {
    /// Full canonical route label from the session owner.
    pub route_ref: String,
    /// Adapter/factory identity.
    pub adapter_id: String,
    /// Adapter revision; nonzero.
    pub adapter_revision: u64,
    /// Lowercase SHA-256 of the admitted worker configuration bytes.
    pub config_digest: String,
    /// Facet manifest reference.
    pub facet_manifest_ref: String,
    /// Grant-graph revision the binding was compiled against; nonzero.
    pub grant_graph_revision: u64,
    /// Replay stream identity bound to this claim.
    pub replay_stream_id: String,
    /// Claim-bound launch nonce (16..=256 chars, mirroring T9-01).
    pub launch_nonce: String,
    /// Lowercase SHA-256 of the exact process invocation.
    pub process_invocation_digest: String,
    /// Authority epoch; must agree with `state_fence` via
    /// `is_same_authority`, never by raw sequence comparison.
    pub authority_epoch: EpochId,
    /// Resource generation; must equal `state_fence.resource_generation`.
    pub generation: ResourceGeneration,
    /// Exact immutable fence the binding was compiled against.
    pub state_fence: StateFence,
    /// Execution deadline in Unix milliseconds; nonzero, before expiry.
    pub deadline_unix_ms: u64,
    /// Binding expiry in Unix milliseconds; nonzero, after deadline.
    pub expires_at_unix_ms: u64,
    /// Owner binding wire revision; must equal
    /// [`NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION`].
    pub executable_wire_version: u16,
    /// Opaque owner-produced executable digest (lowercase SHA-256).
    pub executable_binding_digest: String,
}

impl NativeWorkerExecutableBinding {
    /// Minimum presented launch-nonce length (mirrors T9-01).
    pub const MIN_NONCE_LEN: usize = 16;
    /// Maximum presented launch-nonce length (mirrors T9-01).
    pub const MAX_NONCE_LEN: usize = 256;

    /// Validates the closed join shape without treating it as authority.
    ///
    /// Checks bounded texts, digest shapes, nonzero revisions, the
    /// deadline-before-expiry window, and fence/epoch/generation agreement.
    /// Digest equality against the current owner record is checked by
    /// [`NativeWorkerClaim::require_executable_binding`], not here.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for a malformed, unbounded,
    /// or disagreeing shape field, [`WorkerError::UnsupportedVersion`] for
    /// an unknown executable wire version, [`WorkerError::StaleEpoch`] for
    /// epoch disagreement, and [`WorkerError::StaleFence`] for
    /// generation/fence disagreement.
    pub fn validate(&self) -> Result<(), WorkerError> {
        for (text, field) in [
            (&self.route_ref, "executable_binding.route_ref"),
            (&self.adapter_id, "executable_binding.adapter_id"),
            (
                &self.facet_manifest_ref,
                "executable_binding.facet_manifest_ref",
            ),
            (
                &self.replay_stream_id,
                "executable_binding.replay_stream_id",
            ),
        ] {
            validate_claim_text(text, field)?;
        }
        validate_claim_text(&self.launch_nonce, "executable_binding.launch_nonce")?;
        if self.launch_nonce.len() < Self::MIN_NONCE_LEN
            || self.launch_nonce.len() > Self::MAX_NONCE_LEN
        {
            return Err(WorkerError::InvalidRequest(
                "executable_binding.launch_nonce",
            ));
        }
        for (digest, field) in [
            (&self.config_digest, "executable_binding.config_digest"),
            (
                &self.process_invocation_digest,
                "executable_binding.process_invocation_digest",
            ),
            (
                &self.executable_binding_digest,
                "executable_binding.executable_binding_digest",
            ),
        ] {
            if !is_lowercase_sha256(digest) {
                return Err(WorkerError::InvalidRequest(field));
            }
        }
        if self.adapter_revision == 0 || self.grant_graph_revision == 0 {
            return Err(WorkerError::InvalidRequest("executable_binding.revisions"));
        }
        if self.generation.value() == 0 {
            return Err(WorkerError::InvalidRequest("executable_binding.generation"));
        }
        if self.executable_wire_version != NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION {
            return Err(WorkerError::UnsupportedVersion);
        }
        if self.deadline_unix_ms == 0 || self.expires_at_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest("executable_binding.deadlines"));
        }
        if self.deadline_unix_ms >= self.expires_at_unix_ms {
            return Err(WorkerError::InvalidRequest("executable_binding.deadlines"));
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("executable_binding.state_fence"))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(WorkerError::StaleEpoch);
        }
        if self.generation != self.state_fence.resource_generation {
            return Err(WorkerError::StaleFence);
        }
        Ok(())
    }
}

/// Current owner-produced executable authority one claim is checked against.
///
/// The route builds this from the live registration, admission, activation,
/// and epoch records at admission time: `current` is what the owner says the
/// binding is now, and `revoked` carries observed invalidation evidence (the
/// binding was withdrawn or superseded after publication). This side never
/// mints this value; it only refuses presented claims that disagree with it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerExecutableExpectation {
    /// Owner-produced current executable record.
    pub current: NativeWorkerExecutableBinding,
    /// True when current records show the binding withdrawn or superseded.
    pub revoked: bool,
}

/// Returns the default claim-wire revision for payloads that predate the
/// executable join (wire v1, no `wire_version` key).
fn native_claim_wire_v1() -> u16 {
    NATIVE_WORKER_CLAIM_WIRE_VERSION_V1
}

/// One Kernel-owned execution unit claimed by exactly one admitted worker
/// generation.
///
/// The claim binds the parent Durable Job id, the task/`WorkScope` id, the
/// logical decision id, the attempt id, the operation id, the route/provider
/// class label, the budget, the deadline, the cancellation policy id, the
/// expected result schema, and the predecessor revision. The route/provider
/// class is an admitted label only: this contour never selects a provider,
/// model, or factory. `binding_digest` is the canonical digest over every
/// bound work field; the same claim identity presented with changed work,
/// generation, route, budget, schema, fence, or predecessor is a [`ClaimBindingDecision::Conflict`],
/// never a silent supersede.
///
/// Wire v2 (T9-02) additionally binds `executable_binding`, the
/// owner-produced executable join. Wire v1 parses (its join decodes as
/// absent) but can never carry executable authority; unknown wires are
/// rejected as [`WorkerError::UnsupportedVersion`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerClaim {
    /// Distinct claim operation identity; at most one live claim per id.
    pub claim_id: NativeClaimId,
    /// Registration this claim is presented under.
    pub registration_id: NativeRegistrationId,
    /// Claiming worker generation; stale generations cannot claim.
    pub worker_generation: u64,
    /// Kernel-owned parent Durable Job identity.
    pub parent_job_id: String,
    /// Governed task identity.
    pub task_id: TaskId,
    /// Task `WorkScope` identity.
    pub work_scope_id: String,
    /// Logical decision this attempt executes.
    pub decision_id: DecisionId,
    /// Attempt identity bound to this claim.
    pub attempt_id: AttemptId,
    /// Exact external-effect operation identity.
    pub operation_id: OperationId,
    /// Admitted route/provider class label. Selection stays with #874.
    pub route_class: String,
    /// Resource and context ceilings for the unit.
    pub budget: BudgetEnvelope,
    /// Claim deadline in Unix milliseconds; nonzero.
    pub deadline_unix_ms: u64,
    /// Cancellation policy governing this unit.
    pub cancellation_policy_id: String,
    /// Expected result schema name.
    pub expected_result_schema: String,
    /// Expected result schema version; nonzero.
    pub expected_result_schema_version: u16,
    /// Predecessor revision this claim continues from.
    pub predecessor_revision: String,
    /// Current authority epoch; must equal `state_fence.authority_epoch`.
    pub authority_epoch: EpochId,
    /// Exact immutable fence paired with the generation and epoch.
    pub state_fence: StateFence,
    /// Claim-wire revision. Defaults to v1 for payloads that predate the
    /// executable join so old-wire claims still parse; v1 can never carry
    /// executable authority and unknown revisions are rejected as
    /// [`WorkerError::UnsupportedVersion`].
    #[serde(default = "native_claim_wire_v1")]
    pub wire_version: u16,
    /// T9-02 executable join: owner-produced digest plus M1 currentness
    /// inputs. Absent (`None`) on wire v1, which predates the join and can
    /// never carry executable authority; required on wire v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_binding: Option<NativeWorkerExecutableBinding>,
    /// Canonical digest over every bound work field (see
    /// [`NativeWorkerClaim::compute_binding_digest`]).
    pub binding_digest: String,
}

impl NativeWorkerClaim {
    /// Computes the canonical binding digest over every bound work field.
    ///
    /// The digest covers exactly these keys: `attempt_id`,
    /// `authority_epoch`, `budget`, `cancellation_policy_id`, `claim_id`,
    /// `deadline_unix_ms`, `decision_id`, `executable_binding`,
    /// `expected_result_schema`, `expected_result_schema_version`,
    /// `operation_id`, `parent_job_id`, `predecessor_revision`,
    /// `registration_id`, `route_class`, `state_fence`, `task_id`,
    /// `work_scope_id`, `worker_generation`. The nested `executable_binding`
    /// object is JSON `null` for wire-v1 claims (which predate the join) and
    /// otherwise covers exactly the keys `adapter_id`, `adapter_revision`,
    /// `authority_epoch`, `config_digest`, `deadline_unix_ms`,
    /// `executable_binding_digest`, `executable_wire_version`,
    /// `expires_at_unix_ms`, `facet_manifest_ref`, `generation`,
    /// `grant_graph_revision`, `launch_nonce`, `process_invocation_digest`,
    /// `replay_stream_id`, `route_ref`, `state_fence`, with object keys
    /// sorted recursively before hashing. This matches the Kernel-side
    /// `NativeWorkerClaimRequest::compute_binding_digest` byte-for-byte: the
    /// worker-side transparent string newtypes and the Kernel-side plain
    /// strings serialize to identical JSON, and the epoch/fence/generation
    /// values on both sides come from the same `eliot-contracts` types, so
    /// equal logical claims yield equal digests on both sides.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] when the canonical form
    /// cannot be encoded.
    pub fn compute_binding_digest(&self) -> Result<String, WorkerError> {
        let canonical = serde_json::json!({
            "attempt_id": self.attempt_id,
            "authority_epoch": self.authority_epoch,
            "budget": self.budget,
            "cancellation_policy_id": self.cancellation_policy_id,
            "claim_id": self.claim_id,
            "deadline_unix_ms": self.deadline_unix_ms,
            "decision_id": self.decision_id,
            "executable_binding": self.executable_binding,
            "expected_result_schema": self.expected_result_schema,
            "expected_result_schema_version": self.expected_result_schema_version,
            "operation_id": self.operation_id,
            "parent_job_id": self.parent_job_id,
            "predecessor_revision": self.predecessor_revision,
            "registration_id": self.registration_id,
            "route_class": self.route_class,
            "state_fence": self.state_fence,
            "task_id": self.task_id,
            "work_scope_id": self.work_scope_id,
            "worker_generation": self.worker_generation,
        });
        let bytes = canonical_json_bytes(&canonical)
            .map_err(|_| WorkerError::InvalidRequest("binding_digest"))?;
        Ok(sha256_hex(&bytes))
    }

    /// Returns this claim with its canonical binding digest populated.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] when the canonical form
    /// cannot be encoded.
    #[must_use = "the digest-bearing claim must be used"]
    pub fn with_computed_digest(mut self) -> Result<Self, WorkerError> {
        self.binding_digest = self.compute_binding_digest()?;
        Ok(self)
    }

    /// Validates the closed claim shape, every binding, and the digest.
    ///
    /// Wire v1 (including payloads that predate the `wire_version` key)
    /// parses but must not carry a join; wire v2 must carry a valid join.
    /// Unknown wire revisions are rejected as
    /// [`WorkerError::UnsupportedVersion`], never promoted.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnsupportedVersion`] for an unknown wire
    /// revision and [`WorkerError::InvalidRequest`] for any malformed,
    /// unbounded, disagreeing, or digest-mismatching field.
    pub fn validate(&self) -> Result<(), WorkerError> {
        if self.wire_version != NATIVE_WORKER_CLAIM_WIRE_VERSION
            && self.wire_version != NATIVE_WORKER_CLAIM_WIRE_VERSION_V1
        {
            return Err(WorkerError::UnsupportedVersion);
        }
        for (text, field) in [
            (&self.parent_job_id, "parent_job_id"),
            (&self.work_scope_id, "work_scope_id"),
            (&self.route_class, "route_class"),
            (&self.cancellation_policy_id, "cancellation_policy_id"),
            (&self.expected_result_schema, "expected_result_schema"),
            (&self.predecessor_revision, "predecessor_revision"),
        ] {
            validate_claim_text(text, field)?;
        }
        if self.worker_generation == 0
            || self.deadline_unix_ms == 0
            || self.expected_result_schema_version == 0
        {
            return Err(WorkerError::InvalidRequest("bounded_fields"));
        }
        self.budget
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("budget"))?;
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("state_fence"))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(WorkerError::InvalidRequest("epoch_fence"));
        }
        if !is_lowercase_sha256(&self.binding_digest) {
            return Err(WorkerError::InvalidRequest("binding_digest"));
        }
        if self.wire_version == NATIVE_WORKER_CLAIM_WIRE_VERSION_V1 {
            if self.executable_binding.is_some() {
                return Err(WorkerError::InvalidRequest("executable_binding"));
            }
        } else {
            self.require_present_join()?;
        }
        if self.compute_binding_digest()? != self.binding_digest {
            return Err(WorkerError::InvalidRequest("binding_digest"));
        }
        Ok(())
    }

    /// Returns the validated wire-v2 executable join.
    ///
    /// Wire v1 has no join by construction; callers branch on the wire
    /// version first and only call this on v2.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] when the v2 claim carries no
    /// join or the join shape is malformed.
    fn require_present_join(&self) -> Result<&NativeWorkerExecutableBinding, WorkerError> {
        let join = self
            .executable_binding
            .as_ref()
            .ok_or(WorkerError::InvalidRequest("executable_binding"))?;
        join.validate()?;
        Ok(join)
    }

    /// Enforces the owner-produced executable binding join (T9-02, M1).
    ///
    /// Compares the presented wire-v2 join against the current owner record
    /// supplied by the route from the live registration, admission,
    /// activation, and epoch records. The presented claim binding digest is
    /// recomputed (it covers the join), the carried owner digest must equal
    /// the current owner digest, and every M1 currentness input must agree.
    /// Epoch agreement always goes through `is_same_authority`, never through
    /// a raw sequence comparison. A stale binding — changed route, adapter,
    /// config, facet, grant revision, nonce, stream, invocation digest, or
    /// owner digest; advanced epoch; withdrawn authority; expired window;
    /// fence disagreement — is refused; it needs a new admission, never a
    /// local repair.
    ///
    /// Callers run [`NativeWorkerClaim::validate`] first; this gate checks
    /// the join, not the full envelope shape.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for an old-wire or malformed
    /// presentation, [`WorkerError::UnsupportedVersion`] for an unknown wire,
    /// [`WorkerError::StaleEpoch`] for epoch disagreement,
    /// [`WorkerError::StaleFence`] for fence/generation disagreement,
    /// [`WorkerError::DeadlineExpired`] for an expired binding window, and
    /// [`WorkerError::Revoked`] when current records show the binding
    /// withdrawn or superseded.
    pub fn require_executable_binding(
        &self,
        expected: &NativeWorkerExecutableExpectation,
        now_unix_ms: u64,
    ) -> Result<(), WorkerError> {
        if self.wire_version == NATIVE_WORKER_CLAIM_WIRE_VERSION_V1 {
            return Err(WorkerError::InvalidRequest(
                "u1_old_wire_without_executable_binding",
            ));
        }
        if self.wire_version != NATIVE_WORKER_CLAIM_WIRE_VERSION {
            return Err(WorkerError::UnsupportedVersion);
        }
        let presented = self.require_present_join()?;
        expected.current.validate()?;
        if expected.revoked {
            return Err(WorkerError::Revoked("executable_binding".to_owned()));
        }
        if self.compute_binding_digest()? != self.binding_digest {
            return Err(WorkerError::InvalidRequest("binding_digest"));
        }
        compare_executable_currentness(presented, &expected.current)?;
        if !presented
            .authority_epoch
            .is_same_authority(&self.authority_epoch)
        {
            return Err(WorkerError::StaleEpoch);
        }
        if presented.state_fence != self.state_fence {
            return Err(WorkerError::StaleFence);
        }
        if now_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest(
                "executable_binding.observation_time",
            ));
        }
        if now_unix_ms >= presented.expires_at_unix_ms {
            return Err(WorkerError::DeadlineExpired);
        }
        Ok(())
    }

    /// Compares this (admitted) claim with a presented claim under the same
    /// lineage and reports the same-binding decision.
    ///
    /// A different claim identity is [`ClaimBindingDecision::DifferentClaim`].
    /// The same identity with identical bound work is
    /// [`ClaimBindingDecision::SameBinding`]. The same identity with changed
    /// work, generation, route, budget, schema, fence, epoch, deadline,
    /// cancellation policy, attempt, operation, registration, predecessor,
    /// wire version, or executable join is [`ClaimBindingDecision::Conflict`],
    /// naming every changed dimension.
    /// A bare digest mismatch with otherwise identical work is reported as a
    /// conflict on `binding_digest` itself.
    #[must_use]
    pub fn compare_binding(&self, other: &Self) -> ClaimBindingDecision {
        if self.claim_id != other.claim_id {
            return ClaimBindingDecision::DifferentClaim;
        }
        let mut changed: Vec<String> = Vec::new();
        let mut note = |same: bool, field: &'static str| {
            if !same {
                changed.push(field.to_owned());
            }
        };
        note(
            self.registration_id == other.registration_id,
            "registration_id",
        );
        note(
            self.worker_generation == other.worker_generation,
            "worker_generation",
        );
        note(self.parent_job_id == other.parent_job_id, "parent_job_id");
        note(self.task_id == other.task_id, "task_id");
        note(self.work_scope_id == other.work_scope_id, "work_scope_id");
        note(self.decision_id == other.decision_id, "decision_id");
        note(self.attempt_id == other.attempt_id, "attempt_id");
        note(self.operation_id == other.operation_id, "operation_id");
        note(self.route_class == other.route_class, "route_class");
        note(self.budget == other.budget, "budget");
        note(
            self.deadline_unix_ms == other.deadline_unix_ms,
            "deadline_unix_ms",
        );
        note(
            self.cancellation_policy_id == other.cancellation_policy_id,
            "cancellation_policy_id",
        );
        note(
            self.expected_result_schema == other.expected_result_schema,
            "expected_result_schema",
        );
        note(
            self.expected_result_schema_version == other.expected_result_schema_version,
            "expected_result_schema_version",
        );
        note(
            self.predecessor_revision == other.predecessor_revision,
            "predecessor_revision",
        );
        note(
            self.authority_epoch
                .is_same_authority(&other.authority_epoch),
            "authority_epoch",
        );
        note(self.state_fence == other.state_fence, "state_fence");
        note(self.wire_version == other.wire_version, "wire_version");
        note(
            self.executable_binding == other.executable_binding,
            "executable_binding",
        );
        if changed.is_empty() && self.binding_digest != other.binding_digest {
            changed.push("binding_digest".to_owned());
        }
        if changed.is_empty() {
            ClaimBindingDecision::SameBinding
        } else {
            ClaimBindingDecision::Conflict(ClaimConflict {
                claim_id: self.claim_id.clone(),
                expected_digest: self.binding_digest.clone(),
                observed_digest: other.binding_digest.clone(),
                changed_fields: changed,
            })
        }
    }
}

/// Compares one well-formed presented join against the current owner record.
///
/// The carried owner digest must equal the current owner digest, and every
/// M1 currentness input must agree exactly. Epoch agreement always goes
/// through `is_same_authority`, never through a raw sequence comparison.
/// Checks follow the documented absent-input order (route, adapter, config,
/// facet, grant, stream, nonce, invocation, digest, wire, epoch,
/// generation, fence) so the first reported field is the first missing
/// input callers must supply.
///
/// # Errors
///
/// Returns [`WorkerError::InvalidRequest`] for a changed join field,
/// [`WorkerError::UnsupportedVersion`] for an executable-wire drift,
/// [`WorkerError::StaleEpoch`] for epoch disagreement, and
/// [`WorkerError::StaleFence`] for generation/fence disagreement.
fn compare_executable_currentness(
    presented: &NativeWorkerExecutableBinding,
    current: &NativeWorkerExecutableBinding,
) -> Result<(), WorkerError> {
    if presented.route_ref != current.route_ref {
        return Err(WorkerError::InvalidRequest("executable_binding.route_ref"));
    }
    if presented.adapter_id != current.adapter_id
        || presented.adapter_revision != current.adapter_revision
    {
        return Err(WorkerError::InvalidRequest("executable_binding.adapter"));
    }
    if presented.config_digest != current.config_digest {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.config_digest",
        ));
    }
    if presented.facet_manifest_ref != current.facet_manifest_ref {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.facet_manifest_ref",
        ));
    }
    if presented.grant_graph_revision != current.grant_graph_revision {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.grant_graph_revision",
        ));
    }
    if presented.replay_stream_id != current.replay_stream_id {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.replay_stream_id",
        ));
    }
    if presented.launch_nonce != current.launch_nonce {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.launch_nonce",
        ));
    }
    if presented.process_invocation_digest != current.process_invocation_digest {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.process_invocation_digest",
        ));
    }
    if presented.executable_binding_digest != current.executable_binding_digest {
        return Err(WorkerError::InvalidRequest(
            "executable_binding.executable_binding_digest",
        ));
    }
    if presented.executable_wire_version != current.executable_wire_version {
        return Err(WorkerError::UnsupportedVersion);
    }
    if !presented
        .authority_epoch
        .is_same_authority(&current.authority_epoch)
    {
        return Err(WorkerError::StaleEpoch);
    }
    if presented.generation != current.generation {
        return Err(WorkerError::StaleFence);
    }
    if presented.state_fence != current.state_fence {
        return Err(WorkerError::StaleFence);
    }
    Ok(())
}

/// Same-binding decision for one presented claim identity.
///
/// Mirrors the durable `New / Replay / Conflict` discipline at the claim
/// layer: an unknown identity is a different claim, an identical binding
/// replays, and changed work under one identity conflicts before effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum ClaimBindingDecision {
    /// The presented binding is identical to the admitted one.
    SameBinding,
    /// The same claim identity carries changed bound work.
    Conflict(ClaimConflict),
    /// A different claim identity; not a conflict.
    DifferentClaim,
}

/// Changed-work conflict under one claim identity.
///
/// `expected_digest` is the admitted binding digest, `observed_digest` the
/// presented one, and `changed_fields` names every bound dimension that
/// differs, in canonical field order.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimConflict {
    /// Claim identity both bindings were presented under.
    pub claim_id: NativeClaimId,
    /// Admitted binding digest.
    pub expected_digest: String,
    /// Presented binding digest.
    pub observed_digest: String,
    /// Bound dimensions that differ, in canonical field order.
    pub changed_fields: Vec<String>,
}

/// Dimension that keeps one worker generation from accepting a claimed unit.
///
/// `Ready` is reported only when none of these dimensions blocks; a blocked
/// report names exactly one dimension plus a bounded human-readable reason.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessBlockDimension {
    /// The presenting generation is not the current admitted generation.
    Generation,
    /// The claim binding does not match the admitted claim.
    ClaimBinding,
    /// Required capabilities or resource envelope are unavailable.
    Resources,
    /// The adapter-registry revision is unknown or incompatible.
    AdapterRegistry,
    /// A credential reference is missing, revoked, or unresolvable.
    Credentials,
    /// The claim deadline has passed or is otherwise unusable.
    Deadline,
    /// The epoch or fence is stale or disagrees with the claim.
    Fence,
}

/// Ready report submitted after the worker validates generation, claim,
/// resources, adapter-registry revision, credential references, deadline,
/// and fence.
///
/// The report carries no transport-health field by construction: a live pipe
/// or healthy process alone can never satisfy
/// [`NativeReadyReport::validate_for_claim`]. Only the exact current
/// generation bound to the exact admitted claim is ready.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReadyReport {
    /// Distinct ready-submission operation identity.
    pub ready_id: NativeReadyId,
    /// Claimed unit this report accepts.
    pub claim_id: NativeClaimId,
    /// Registration the claim was presented under.
    pub registration_id: NativeRegistrationId,
    /// Generation accepting the unit; must be current.
    pub worker_generation: u64,
    /// Current authority epoch; must equal `state_fence.authority_epoch`.
    pub authority_epoch: EpochId,
    /// Exact immutable fence paired with the generation and epoch.
    pub state_fence: StateFence,
    /// Echo of the admitted claim binding digest.
    pub claim_binding_digest: String,
    /// Adapter-registry revision (issue #874) validated for this unit.
    pub adapter_registry_revision: String,
    /// Credential references required for this unit. References only; raw
    /// credential bytes or secrets never appear here.
    pub credential_refs: Vec<SecretRef>,
    /// Report time in Unix milliseconds; nonzero.
    pub ready_at_unix_ms: u64,
}

impl NativeReadyReport {
    /// Validates this report against the exact admitted claim.
    ///
    /// Checks identity binding (claim, registration, generation), epoch/fence
    /// agreement with the claim, digest equality with the claim's recomputed
    /// binding digest, adapter-registry revision presence, credential
    /// reference shape, and that the claim deadline still holds at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for a malformed report or
    /// binding mismatch, [`WorkerError::StaleEpoch`]/[`WorkerError::StaleFence`]
    /// for epoch/fence disagreement, and [`WorkerError::DeadlineExpired`]
    /// when the claim deadline no longer holds.
    pub fn validate_for_claim(
        &self,
        claim: &NativeWorkerClaim,
        now_unix_ms: u64,
    ) -> Result<(), WorkerError> {
        claim.validate()?;
        self.validate_binding(claim)?;
        validate_claim_text(&self.adapter_registry_revision, "adapter_registry_revision")?;
        if self.credential_refs.len() > MAX_CREDENTIAL_REFERENCES {
            return Err(WorkerError::InvalidRequest("credential_refs"));
        }
        for reference in &self.credential_refs {
            validate_claim_text(reference.provider(), "credential_refs")?;
            validate_claim_text(reference.key(), "credential_refs")?;
        }
        if self.ready_at_unix_ms == 0 || now_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest("bounded_fields"));
        }
        if claim.deadline_unix_ms <= now_unix_ms || self.ready_at_unix_ms > claim.deadline_unix_ms {
            return Err(WorkerError::DeadlineExpired);
        }
        Ok(())
    }

    /// Checks the identity, generation, epoch, fence, and digest binding
    /// against the admitted claim, shared by ready and blocked reports.
    fn validate_binding(&self, claim: &NativeWorkerClaim) -> Result<(), WorkerError> {
        if self.claim_id != claim.claim_id || self.registration_id != claim.registration_id {
            return Err(WorkerError::InvalidRequest("claim_binding"));
        }
        if self.worker_generation == 0 || self.worker_generation != claim.worker_generation {
            return Err(WorkerError::InvalidRequest("generation_binding"));
        }
        if !self
            .authority_epoch
            .is_same_authority(&claim.authority_epoch)
        {
            return Err(WorkerError::StaleEpoch);
        }
        if self.state_fence != claim.state_fence {
            return Err(WorkerError::StaleFence);
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("state_fence"))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(WorkerError::InvalidRequest("epoch_fence"));
        }
        if !is_lowercase_sha256(&self.claim_binding_digest)
            || self.claim_binding_digest != claim.compute_binding_digest()?
        {
            return Err(WorkerError::InvalidRequest("claim_binding"));
        }
        Ok(())
    }
}

/// Blocked report submitted when the worker cannot accept the claimed unit.
///
/// Carries the same identity binding as [`NativeReadyReport`] so Kernel can
/// attribute the block, plus exactly one [`ReadinessBlockDimension`] and a
/// bounded reason. A block caused by an expired deadline is a legitimate
/// report: unlike [`NativeReadyReport::validate_for_claim`], this method
/// never rejects an expired claim deadline.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBlockedReport {
    /// Distinct submission operation identity for this blocked report.
    pub ready_id: NativeReadyId,
    /// Claimed unit this report refuses.
    pub claim_id: NativeClaimId,
    /// Registration the claim was presented under.
    pub registration_id: NativeRegistrationId,
    /// Generation refusing the unit.
    pub worker_generation: u64,
    /// Authority epoch observed by the refusing generation.
    pub authority_epoch: EpochId,
    /// Fence observed by the refusing generation.
    pub state_fence: StateFence,
    /// Echo of the admitted claim binding digest.
    pub claim_binding_digest: String,
    /// The single dimension that blocks acceptance.
    pub dimension: ReadinessBlockDimension,
    /// Bounded human-readable reason naming the missing proof.
    pub reason: String,
    /// Observation time in Unix milliseconds; nonzero.
    pub observed_at_unix_ms: u64,
}

impl NativeBlockedReport {
    /// Validates this report against the exact admitted claim.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for a malformed report or
    /// binding mismatch, [`WorkerError::StaleEpoch`]/[`WorkerError::StaleFence`]
    /// for epoch/fence disagreement.
    pub fn validate_for_claim(&self, claim: &NativeWorkerClaim) -> Result<(), WorkerError> {
        claim.validate()?;
        if self.claim_id != claim.claim_id || self.registration_id != claim.registration_id {
            return Err(WorkerError::InvalidRequest("claim_binding"));
        }
        if self.worker_generation == 0 || self.worker_generation != claim.worker_generation {
            return Err(WorkerError::InvalidRequest("generation_binding"));
        }
        if !self
            .authority_epoch
            .is_same_authority(&claim.authority_epoch)
        {
            return Err(WorkerError::StaleEpoch);
        }
        if self.state_fence != claim.state_fence {
            return Err(WorkerError::StaleFence);
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("state_fence"))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(WorkerError::InvalidRequest("epoch_fence"));
        }
        if !is_lowercase_sha256(&self.claim_binding_digest)
            || self.claim_binding_digest != claim.compute_binding_digest()?
        {
            return Err(WorkerError::InvalidRequest("claim_binding"));
        }
        validate_claim_text(&self.reason, "blocked_reason")?;
        if self.observed_at_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest("bounded_fields"));
        }
        Ok(())
    }
}

/// Typed ready-or-blocked readiness result.
///
/// The worker submits exactly one of these after validating generation,
/// claim, resources, adapter-registry revision, credential references,
/// deadline, and fence. Transport health alone satisfies neither variant:
/// there is no transport-health field anywhere in this result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum NativeWorkerReadiness {
    /// The exact current generation accepts the exact claimed unit.
    Ready(NativeReadyReport),
    /// The generation refuses the unit along one blocking dimension.
    Blocked(NativeBlockedReport),
}

/// Exact identity tuple every later-wave lifecycle envelope must bind.
///
/// Heartbeat, checkpoint, cancellation, result, and acknowledgement envelopes
/// (Waves C-D) all carry this tuple so Kernel can attribute each message to
/// one worker generation, one claim, one attempt, one operation, one
/// route/provider class, one predecessor revision, and one fence. Lifecycle
/// transitions for those operations land in later waves; the identity tuple
/// is frozen here so downstream writers build on these types.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLifecycleBinding {
    /// Claimed unit this binding belongs to.
    pub claim_id: NativeClaimId,
    /// Attempt identity bound to the claim.
    pub attempt_id: AttemptId,
    /// Exact external-effect operation identity.
    pub operation_id: OperationId,
    /// Worker generation presenting this binding; nonzero.
    pub worker_generation: u64,
    /// Admitted route/provider class label.
    pub route_class: String,
    /// Predecessor revision this binding continues from.
    pub predecessor_revision: String,
    /// Current authority epoch; must equal `state_fence.authority_epoch`.
    pub authority_epoch: EpochId,
    /// Exact immutable fence paired with the generation and epoch.
    pub state_fence: StateFence,
}

impl NativeLifecycleBinding {
    /// Validates the closed binding shape and fence agreement.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for any malformed,
    /// unbounded, or disagreeing field.
    pub fn validate(&self) -> Result<(), WorkerError> {
        validate_claim_text(&self.route_class, "route_class")?;
        validate_claim_text(&self.predecessor_revision, "predecessor_revision")?;
        if self.worker_generation == 0 {
            return Err(WorkerError::InvalidRequest("bounded_fields"));
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("state_fence"))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(WorkerError::InvalidRequest("epoch_fence"));
        }
        Ok(())
    }
}

/// Heartbeat identity envelope (lifecycle transitions in Wave C).
///
/// Heartbeat proves generation liveness only. It creates no task progress,
/// provider success, authority, or completion; only an admitted claim plus a
/// ready report can do that.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHeartbeatEnvelope {
    /// Distinct heartbeat operation identity.
    pub heartbeat_id: NativeHeartbeatId,
    /// Exact lifecycle binding this heartbeat is observed under.
    pub binding: NativeLifecycleBinding,
    /// Observation time in Unix milliseconds; nonzero.
    pub observed_at_unix_ms: u64,
}

impl NativeHeartbeatEnvelope {
    /// Validates the heartbeat identity and its lifecycle binding.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for any malformed field.
    pub fn validate(&self) -> Result<(), WorkerError> {
        self.binding.validate()?;
        if self.observed_at_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest("bounded_fields"));
        }
        Ok(())
    }
}

/// Checkpoint identity envelope (lifecycle transitions in Wave C).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCheckpointEnvelope {
    /// Distinct checkpoint operation identity.
    pub checkpoint_id: NativeCheckpointId,
    /// Exact lifecycle binding this checkpoint is stored under.
    pub binding: NativeLifecycleBinding,
    /// Checkpoint reference assigned by the durable owner.
    pub checkpoint_ref: String,
    /// Observation time in Unix milliseconds; nonzero.
    pub observed_at_unix_ms: u64,
}

impl NativeCheckpointEnvelope {
    /// Validates the checkpoint identity and its lifecycle binding.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for any malformed field.
    pub fn validate(&self) -> Result<(), WorkerError> {
        self.binding.validate()?;
        validate_claim_text(&self.checkpoint_ref, "checkpoint_ref")?;
        if self.observed_at_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest("bounded_fields"));
        }
        Ok(())
    }
}

/// Cancellation observation envelope (lifecycle transitions in Wave C).
///
/// Observes cancellation for one exact attempt; it stops new provider
/// effects and preserves possible work/result state for reconciliation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCancellationEnvelope {
    /// Distinct cancellation-observation operation identity.
    pub cancellation_id: NativeCancellationId,
    /// Exact lifecycle binding this observation cancels.
    pub binding: NativeLifecycleBinding,
    /// Bounded reason for the cancellation observation.
    pub reason: String,
    /// Observation time in Unix milliseconds; nonzero.
    pub observed_at_unix_ms: u64,
}

impl NativeCancellationEnvelope {
    /// Validates the cancellation identity and its lifecycle binding.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for any malformed field.
    pub fn validate(&self) -> Result<(), WorkerError> {
        self.binding.validate()?;
        validate_claim_text(&self.reason, "cancellation_reason")?;
        if self.observed_at_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest("bounded_fields"));
        }
        Ok(())
    }
}

/// Result submission envelope (lifecycle transitions in Wave C).
///
/// Submits one result digest for one exact attempt under the claim's expected
/// result schema. Submission is not acceptance: Kernel reconciles it under
/// the original claim before any reclaim or retry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeResultEnvelope {
    /// Distinct result-submission operation identity.
    pub result_id: NativeResultId,
    /// Exact lifecycle binding this result is submitted under.
    pub binding: NativeLifecycleBinding,
    /// Result schema name; must match the claim's expected schema at
    /// admission.
    pub result_schema: String,
    /// Result schema version; nonzero.
    pub result_schema_version: u16,
    /// Lowercase SHA-256 over the canonical result bytes.
    pub result_digest: String,
    /// Submission time in Unix milliseconds; nonzero.
    pub submitted_at_unix_ms: u64,
}

impl NativeResultEnvelope {
    /// Validates the result identity and its lifecycle binding.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for any malformed field.
    pub fn validate(&self) -> Result<(), WorkerError> {
        self.binding.validate()?;
        validate_claim_text(&self.result_schema, "result_schema")?;
        if self.result_schema_version == 0 || self.submitted_at_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest("bounded_fields"));
        }
        if !is_lowercase_sha256(&self.result_digest) {
            return Err(WorkerError::InvalidRequest("result_digest"));
        }
        Ok(())
    }
}

/// Terminal acknowledgement record (lifecycle transitions in Wave D).
///
/// Acknowledges one exact digest (claim receipt, result outcome, or
/// reconciliation verdict) so lost-acknowledgement recovery can reconcile
/// under the original claim instead of reclaiming blindly.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAckRecord {
    /// Distinct acknowledgement operation identity.
    pub ack_id: NativeAckId,
    /// Claimed unit this acknowledgement belongs to.
    pub claim_id: NativeClaimId,
    /// Worker generation acknowledging; nonzero.
    pub worker_generation: u64,
    /// Current authority epoch; must equal `state_fence.authority_epoch`.
    pub authority_epoch: EpochId,
    /// Exact immutable fence paired with the generation and epoch.
    pub state_fence: StateFence,
    /// Lowercase SHA-256 of the exact acknowledged receipt bytes.
    pub acknowledged_digest: String,
    /// Acknowledgement time in Unix milliseconds; nonzero.
    pub acknowledged_at_unix_ms: u64,
}

impl NativeAckRecord {
    /// Validates the acknowledgement identity and fence agreement.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidRequest`] for any malformed or
    /// disagreeing field.
    pub fn validate(&self) -> Result<(), WorkerError> {
        if self.worker_generation == 0 || self.acknowledged_at_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest("bounded_fields"));
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("state_fence"))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(WorkerError::InvalidRequest("epoch_fence"));
        }
        if !is_lowercase_sha256(&self.acknowledged_digest) {
            return Err(WorkerError::InvalidRequest("acknowledged_digest"));
        }
        Ok(())
    }
}
