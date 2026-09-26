//! Authenticated Kernel-to-Host client for UserAutomation execution owners.
//!
//! The client carries only closed, typed projections.  The authenticated
//! transport supplies the existing connection, descriptor, peer-admission
//! receipt, and State Fence binding; this module does not mint a grant,
//! scheduler identity, Durable Job identity, or Host journal record.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use eliot_contracts::{RequestId, RequestMetadata, StateFence, canonical_json_bytes, sha256_hex};
use eliot_ipc::PeerIdentity;
#[cfg(windows)]
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};
use eliot_kernel_core::user_automation::AutomationExecutionReference;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
    RequestIdentity,
};
use eliot_receipts::RequestBinding;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    UserAutomationDurableJobPort, UserAutomationRuntimeAdmission, UserAutomationRuntimeError,
    UserAutomationWakeCancellation, UserAutomationWakePort, UserAutomationWakeReadRequest,
    UserAutomationWakeReadback,
};

/// Stable wire identity for the typed UserAutomation Host execution carrier.
pub const USER_AUTOMATION_HOST_EXECUTION_WIRE_ID: &str = "eliot.user_automation.host_execution";
/// Current semantic revision of the typed UserAutomation Host execution wire.
pub const USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION: u16 = 1;
/// Authenticated Kernel front-door module identity used by the Host owner join.
///
/// This is a transport principal only.  The Kernel derives its requester role
/// from this authenticated session and still validates the typed Dreamer
/// operation and State Fence before calling the canonical Store gateway.
pub const USER_AUTOMATION_KERNEL_MODULE_ID: &str = "eliot-host-user-automation";
/// Dedicated least-privilege capability advertised by the UserAutomation
/// owner session. The outer Dreamer frame still selects the existing
/// `eliot.kernel.dreamer-job` dispatch family, but this capability admits only
/// the UserAutomation Submit arm inside that family.
pub const USER_AUTOMATION_KERNEL_CAPABILITY: &str = "eliot.kernel.user-automation.submit";
/// Existing Kernel dispatch family selected by the typed UserAutomation route.
pub const USER_AUTOMATION_KERNEL_OPERATION: &str = "eliot.kernel.dreamer-job";
/// Privacy class requested by the least-privilege UserAutomation session.
/// The live Kernel policy must still admit this class; the value is never
/// authority by itself.
pub const USER_AUTOMATION_KERNEL_PRIVACY_CLASS: &str = "PUBLIC";
/// Stable server principal projection for the Host owner session.
pub const USER_AUTOMATION_KERNEL_PRINCIPAL_BINDING: &str = "eliot-kernel::host-user-automation:v1";
/// Existing authenticated Host runtime-control pipe carrying this typed route.
pub const USER_AUTOMATION_HOST_EXECUTION_PIPE: &str = r"\\.\pipe\eliot\host\runtime-control-v1";
const USER_AUTOMATION_HOST_EXECUTION_TRACE_KEY: &str =
    "eliot.user_automation.host-execution-discriminator";
const USER_AUTOMATION_HOST_EXECUTION_TRACE_VALUE: &str = "eliot-user-automation::host-execution:v1";
const USER_AUTOMATION_HOST_EXECUTION_OPEN_TRACE_KEY: &str =
    "eliot.user_automation.host-execution-open-discriminator";
const USER_AUTOMATION_HOST_EXECUTION_OPEN_TRACE_VALUE: &str =
    "eliot-user-automation::host-execution-open:v1";

/// Evidence binding supplied by the already authenticated Kernel-to-Host
/// channel.
///
/// These values are transport evidence and selectors only.  They must be
/// copied from the existing authenticated route and never manufactured by a
/// UserAutomation caller.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationHostChannelBinding {
    /// Kernel-created identity of the authenticated transport connection.
    pub connection_id: String,
    /// Digest of the immutable Kernel/Host admission descriptor.
    pub descriptor_sha256: String,
    /// Digest of the authenticated peer-admission receipt.
    pub peer_admission_receipt_sha256: String,
    /// Fence observed by the authenticated channel.
    pub state_fence: StateFence,
}

impl UserAutomationHostChannelBinding {
    /// Issues a server-authored binding from the live authenticated peer and
    /// the retained Host owner anchor. Descriptor and receipt hashes are
    /// derived here; callers cannot supply shape-valid substitutes.
    pub fn issue_server_authored(
        peer: &PeerIdentity,
        owner: &UserAutomationHostOwnerBinding,
    ) -> Result<Self, UserAutomationRuntimeError> {
        owner.validate()?;
        peer.validate()
            .map_err(|_| rejected("UserAutomation peer is not authenticated"))?;
        let nonce = USER_AUTOMATION_SESSION_NONCE.fetch_add(1, Ordering::Relaxed);
        let connection_id = format!("ua-host-connection:{}:{}", std::process::id(), nonce);
        Self::for_authenticated_connection(connection_id, peer, owner)
    }

    fn for_authenticated_connection(
        connection_id: String,
        peer: &PeerIdentity,
        owner: &UserAutomationHostOwnerBinding,
    ) -> Result<Self, UserAutomationRuntimeError> {
        validate_text(&connection_id, "channel.connection_id")?;
        owner.validate()?;
        owner.validate_peer(peer)?;
        let peer_digest = authenticated_peer_evidence_digest(peer)?;
        let peer_admission_receipt_sha256 = sha256_hex(
            &canonical_json_bytes(&(
                "eliot.user_automation.host-peer-admission.v2",
                &connection_id,
                &peer_digest,
                owner,
            ))
            .map_err(|error| rejected(format!("peer admission receipt encoding: {error}")))?,
        );
        let descriptor_sha256 = sha256_hex(
            &canonical_json_bytes(&(
                "eliot.user_automation.host-channel-descriptor.v2",
                &connection_id,
                &peer_admission_receipt_sha256,
                owner,
            ))
            .map_err(|error| rejected(format!("channel descriptor encoding: {error}")))?,
        );
        Ok(Self {
            connection_id,
            descriptor_sha256,
            peer_admission_receipt_sha256,
            state_fence: owner.state_fence.clone(),
        })
    }

    /// Validates the shape and fence of retained channel evidence.
    pub fn validate(&self) -> Result<(), UserAutomationRuntimeError> {
        validate_text(&self.connection_id, "channel.connection_id")?;
        validate_sha256(&self.descriptor_sha256, "channel.descriptor_sha256")?;
        validate_sha256(
            &self.peer_admission_receipt_sha256,
            "channel.peer_admission_receipt_sha256",
        )?;
        self.state_fence
            .validate()
            .map_err(|error| rejected(format!("channel state fence: {error}")))
    }

    /// Recomputes the complete binding from the retained authenticated peer
    /// and owner. A caller-provided digest is never treated as authority.
    pub fn validate_authenticated(
        &self,
        peer: &PeerIdentity,
        owner: &UserAutomationHostOwnerBinding,
    ) -> Result<(), UserAutomationRuntimeError> {
        self.validate()?;
        let expected = Self::for_authenticated_connection(self.connection_id.clone(), peer, owner)?;
        if self != &expected {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Ok(())
    }
}

/// Kernel/activation evidence retained by the Host owner for one inbound
/// UserAutomation connection. This is an in-process authority anchor; it is
/// never accepted from a request payload.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationHostOwnerBinding {
    /// Digest of the retained Host Kernel candidate binding.
    pub candidate_binding_sha256: String,
    /// Digest of the retained Kernel activation receipt.
    pub activation_receipt_sha256: String,
    /// State Fence selected by the retained active contour.
    pub state_fence: StateFence,
    /// Handle-bound Kernel process expected on the authenticated peer.
    pub expected_peer_process_id: u32,
    /// Handle-bound Kernel process start time expected on the peer.
    pub expected_peer_start_time_100ns: u64,
    /// Canonical Kernel image expected on the peer.
    pub expected_peer_image_path: String,
}

impl UserAutomationHostOwnerBinding {
    /// Validates the retained owner anchor and the process identity it pins.
    pub fn validate(&self) -> Result<(), UserAutomationRuntimeError> {
        validate_sha256(
            &self.candidate_binding_sha256,
            "owner.candidate_binding_sha256",
        )?;
        validate_sha256(
            &self.activation_receipt_sha256,
            "owner.activation_receipt_sha256",
        )?;
        self.state_fence
            .validate()
            .map_err(|error| rejected(format!("owner state fence: {error}")))?;
        if self.expected_peer_process_id == 0
            || self.expected_peer_start_time_100ns == 0
            || self.expected_peer_image_path.trim().is_empty()
            || self.expected_peer_image_path.chars().any(char::is_control)
        {
            return Err(rejected("owner expected Kernel process binding is invalid"));
        }
        Ok(())
    }

    fn validate_peer(&self, peer: &PeerIdentity) -> Result<(), UserAutomationRuntimeError> {
        self.validate()?;
        peer.validate()
            .map_err(|_| rejected("UserAutomation peer is not authenticated"))?;
        let process = peer
            .process_binding()
            .ok_or_else(|| rejected("UserAutomation peer process binding is unavailable"))?;
        if process.process_id() != self.expected_peer_process_id
            || process.start_time_100ns() != self.expected_peer_start_time_100ns
            || !process
                .image_path()
                .eq_ignore_ascii_case(&self.expected_peer_image_path)
        {
            return Err(rejected(
                "UserAutomation peer is not the retained Kernel process",
            ));
        }
        Ok(())
    }
}

static USER_AUTOMATION_SESSION_NONCE: AtomicU64 = AtomicU64::new(1);

fn authenticated_peer_evidence_digest(
    peer: &PeerIdentity,
) -> Result<String, UserAutomationRuntimeError> {
    peer.validate()
        .map_err(|_| rejected("UserAutomation peer is not authenticated"))?;
    let process = peer
        .process_binding()
        .ok_or_else(|| rejected("UserAutomation peer process binding is unavailable"))?;
    let PeerIdentity::Authenticated {
        process_id,
        user_identity,
        session_identity,
        ..
    } = peer
    else {
        return Err(rejected("UserAutomation peer is not authenticated"));
    };
    Ok(sha256_hex(
        &canonical_json_bytes(&(
            "eliot.user_automation.authenticated-peer-evidence.v2",
            process_id,
            user_identity,
            session_identity,
            process.process_id(),
            process.start_time_100ns(),
            process.image_path(),
            process.executable_file_identity(),
        ))
        .map_err(|error| rejected(format!("peer evidence encoding: {error}")))?,
    ))
}

/// Opaque server-authored admission context retained beside one queued
/// carrier. The caller's channel fields remain correlation data; owner calls
/// require this context and therefore cannot be admitted by copying a carrier
/// from another connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserAutomationHostExecutionSession {
    server_session_id: String,
    channel: UserAutomationHostChannelBinding,
    request_sha256: String,
    peer: PeerIdentity,
    owner: UserAutomationHostOwnerBinding,
}

impl UserAutomationHostExecutionSession {
    /// Issues a fresh session only after the named-pipe server has authenticated
    /// the actual connected peer. The owner anchor is retained by Host
    /// composition and cannot be supplied by the wire carrier.
    pub fn issue(
        channel: UserAutomationHostChannelBinding,
        request_sha256: impl Into<String>,
        peer: PeerIdentity,
        owner: UserAutomationHostOwnerBinding,
    ) -> Result<Self, UserAutomationRuntimeError> {
        let request_sha256 = request_sha256.into();
        validate_sha256(&request_sha256, "session.request_sha256")?;
        channel.validate_authenticated(&peer, &owner)?;
        let nonce = USER_AUTOMATION_SESSION_NONCE.fetch_add(1, Ordering::Relaxed);
        let peer_process = peer
            .process_binding()
            .ok_or_else(|| rejected("UserAutomation peer process binding is unavailable"))?;
        let server_session_id = sha256_hex(
            &canonical_json_bytes(&(
                "eliot.user_automation.server-session.v1",
                nonce,
                &channel,
                &request_sha256,
                peer_process.process_id(),
                peer_process.start_time_100ns(),
                peer_process.image_path(),
                &owner,
            ))
            .map_err(|error| rejected(format!("UserAutomation session encoding: {error}")))?,
        );
        Ok(Self {
            server_session_id,
            channel,
            request_sha256,
            peer,
            owner,
        })
    }

    /// Validates the exact carrier before it enters the owner queue.
    pub fn authorize_request(
        &self,
        request: &UserAutomationHostExecutionRequest,
    ) -> Result<(), UserAutomationRuntimeError> {
        request.validate()?;
        if request.request_sha256 != self.request_sha256 || request.channel != self.channel {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        self.owner.validate_peer(&self.peer)?;
        Ok(())
    }

    /// Revalidates the live peer retained by this server-authored session.
    /// Owner adapters call this immediately before crossing into the Kernel
    /// front door; the wire carrier cannot replace the peer evidence.
    pub fn validate_authenticated_peer(&self) -> Result<(), UserAutomationRuntimeError> {
        self.owner.validate_peer(&self.peer)
    }

    /// Returns the retained server session identity for exact queue
    /// correlation. It is not a bearer token and is never trusted from a
    /// serialized request.
    #[must_use]
    pub fn server_session_id(&self) -> &str {
        &self.server_session_id
    }

    /// Returns the owner anchor captured when this session was issued.
    #[must_use]
    pub const fn owner(&self) -> &UserAutomationHostOwnerBinding {
        &self.owner
    }

    /// Returns the authenticated peer retained by the server session.
    #[must_use]
    pub const fn peer(&self) -> &PeerIdentity {
        &self.peer
    }
}

/// Closed failure projection returned by the Host endpoint when an owner
/// cannot complete the typed operation. A transport failure remains outside
/// this enum and is classified as an unknown outcome by the client.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationHostExecutionFailure {
    /// The Host owner is not currently available.
    Unavailable {
        /// Closed reason supplied by the Host owner.
        reason: String,
    },
    /// The owner may have committed and the result must be reconciled.
    UnknownOutcome {
        /// Closed reason supplied by the Host owner.
        reason: String,
    },
    /// The typed request was rejected before an owner effect.
    Rejected {
        /// Closed reason supplied by the Host owner.
        reason: String,
    },
    /// The response was bound to another request or fence.
    IdentityConflict,
}

impl UserAutomationHostExecutionFailure {
    fn from_runtime_error(error: UserAutomationRuntimeError) -> Self {
        match error {
            UserAutomationRuntimeError::Unavailable(reason) => Self::Unavailable { reason },
            UserAutomationRuntimeError::UnknownOutcome(reason) => Self::UnknownOutcome { reason },
            UserAutomationRuntimeError::Rejected(reason) => Self::Rejected { reason },
            UserAutomationRuntimeError::IdentityConflict => Self::IdentityConflict,
        }
    }

    fn into_runtime_error(self) -> UserAutomationRuntimeError {
        match self {
            Self::Unavailable { reason } => UserAutomationRuntimeError::Unavailable(reason),
            Self::UnknownOutcome { reason } => UserAutomationRuntimeError::UnknownOutcome(reason),
            Self::Rejected { reason } => UserAutomationRuntimeError::Rejected(reason),
            Self::IdentityConflict => UserAutomationRuntimeError::IdentityConflict,
        }
    }

    /// Validates the closed failure projection shape without inferring success.
    pub fn validate(&self) -> Result<(), UserAutomationRuntimeError> {
        match self {
            Self::Unavailable { reason }
            | Self::UnknownOutcome { reason }
            | Self::Rejected { reason } => validate_text(reason, "failure.reason"),
            Self::IdentityConflict => Ok(()),
        }
    }
}

/// One typed UserAutomation execution operation sent over the authenticated
/// Host channel.
///
/// The three operation payloads differ by more than 2 KiB, so each one is held
/// indirectly and every variant costs the same single pointer. `Box<T>` is a
/// newtype over `T` for serde and schemars, so the externally tagged
/// `tag = "operation"` shape, the `request` member name, the closed
/// `deny_unknown_fields` surface and the canonical digest bytes are unchanged
/// by the indirection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation", deny_unknown_fields)]
pub enum UserAutomationHostExecutionOperation {
    /// Admit one owner-issued occurrence to the existing Durable Job owner.
    AdmitOccurrence {
        /// Authenticated, preflight-approved occurrence admission.
        request: Box<UserAutomationRuntimeAdmission>,
    },
    /// Cancel exact owner-issued future wake targets.
    CancelPendingWakes {
        /// Same-fence, unadmitted-only cancellation request.
        request: Box<UserAutomationWakeCancellation>,
    },
    /// Read one exact retained Pending wake from the Host journal.
    ReadPendingWake {
        /// Original Human RunNow identity and owner-issued invocation.
        request: Box<UserAutomationWakeReadRequest>,
    },
}

/// Typed Kernel-to-Host request carrier for one UserAutomation execution
/// operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationHostExecutionRequest {
    /// Stable carrier wire identity.
    pub wire_id: String,
    /// Carrier semantic revision.
    pub wire_version: u16,
    /// Existing authenticated channel evidence.
    pub channel: UserAutomationHostChannelBinding,
    /// Closed operation payload.
    pub operation: UserAutomationHostExecutionOperation,
    /// Lowercase SHA-256 over the carrier with this field empty.
    pub request_sha256: String,
}

impl UserAutomationHostExecutionRequest {
    /// Builds and hashes one typed admission carrier.
    pub fn admit_occurrence(
        channel: UserAutomationHostChannelBinding,
        request: impl Into<Box<UserAutomationRuntimeAdmission>>,
    ) -> Result<Self, UserAutomationRuntimeError> {
        Self::new(
            channel,
            UserAutomationHostExecutionOperation::AdmitOccurrence {
                request: request.into(),
            },
        )
    }

    /// Builds and hashes one typed wake-cancellation carrier.
    pub fn cancel_pending_wakes(
        channel: UserAutomationHostChannelBinding,
        request: impl Into<Box<UserAutomationWakeCancellation>>,
    ) -> Result<Self, UserAutomationRuntimeError> {
        Self::new(
            channel,
            UserAutomationHostExecutionOperation::CancelPendingWakes {
                request: request.into(),
            },
        )
    }

    /// Builds and hashes one exact pending-wake readback carrier.
    pub fn read_pending_wake(
        channel: UserAutomationHostChannelBinding,
        request: impl Into<Box<UserAutomationWakeReadRequest>>,
    ) -> Result<Self, UserAutomationRuntimeError> {
        Self::new(
            channel,
            UserAutomationHostExecutionOperation::ReadPendingWake {
                request: request.into(),
            },
        )
    }

    fn new(
        channel: UserAutomationHostChannelBinding,
        operation: UserAutomationHostExecutionOperation,
    ) -> Result<Self, UserAutomationRuntimeError> {
        let value = Self {
            wire_id: USER_AUTOMATION_HOST_EXECUTION_WIRE_ID.to_owned(),
            wire_version: USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION,
            channel,
            operation,
            request_sha256: String::new(),
        };
        value.validate_without_digest()?;
        let request_sha256 = value.compute_digest()?;
        let value = Self {
            request_sha256,
            ..value
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the complete typed carrier and its canonical digest.
    pub fn validate(&self) -> Result<(), UserAutomationRuntimeError> {
        self.validate_without_digest()?;
        validate_sha256(&self.request_sha256, "request_sha256")?;
        let expected = self.compute_digest()?;
        if self.request_sha256 != expected {
            return Err(rejected("UserAutomation Host request digest mismatch"));
        }
        Ok(())
    }

    /// Returns the canonical digest used for response correlation.
    pub fn compute_digest(&self) -> Result<String, UserAutomationRuntimeError> {
        let mut unsigned = self.clone();
        unsigned.request_sha256.clear();
        let bytes = canonical_json_bytes(&unsigned)
            .map_err(|error| rejected(format!("UserAutomation Host request encoding: {error}")))?;
        Ok(sha256_hex(&bytes))
    }

    /// Returns the request State Fence without interpreting the operation.
    #[must_use]
    pub fn state_fence(&self) -> &StateFence {
        &self.channel.state_fence
    }

    fn validate_without_digest(&self) -> Result<(), UserAutomationRuntimeError> {
        if self.wire_id != USER_AUTOMATION_HOST_EXECUTION_WIRE_ID
            || self.wire_version != USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION
        {
            return Err(rejected("unsupported UserAutomation Host execution wire"));
        }
        self.channel.validate()?;
        match &self.operation {
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                request
                    .validate()
                    .map_err(|error| rejected(format!("Durable Job admission: {error}")))?;
                if request.durable_job.is_none() {
                    return Err(rejected(
                        "concrete Host Durable Job admission requires owner-issued material",
                    ));
                }
                if request.context.state_fence != self.channel.state_fence {
                    return Err(rejected("admission channel fence mismatch"));
                }
            }
            UserAutomationHostExecutionOperation::CancelPendingWakes { request } => {
                request
                    .validate()
                    .map_err(|error| rejected(format!("Wake cancellation: {error}")))?;
                if request.targets.is_empty() {
                    return Err(rejected(
                        "concrete Host wake cancellation requires owner-issued targets",
                    ));
                }
                if request.state_fence != self.channel.state_fence {
                    return Err(rejected("cancellation channel fence mismatch"));
                }
            }
            UserAutomationHostExecutionOperation::ReadPendingWake { request } => {
                request
                    .validate()
                    .map_err(|error| rejected(format!("wake read: {error}")))?;
                if request.context.state_fence != self.channel.state_fence {
                    return Err(rejected("wake read channel fence mismatch"));
                }
            }
        }
        Ok(())
    }
}

/// Typed response returned by the Host execution endpoint.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result", deny_unknown_fields)]
pub enum UserAutomationHostExecutionResponse {
    /// Durable Job admission result.
    Admitted {
        /// Digest of the exact request carrier answered.
        request_sha256: String,
        /// Fence observed by the Host owner.
        state_fence: StateFence,
        /// Existing Durable Job projection.
        execution: AutomationExecutionReference,
    },
    /// Wake cancellation result.
    Cancelled {
        /// Digest of the exact request carrier answered.
        request_sha256: String,
        /// Fence observed by the Host owner.
        state_fence: StateFence,
        /// Exact wake identities whose cancellation was committed or replayed.
        wake_ids: Vec<String>,
    },
    /// Exact retained wake record returned by the Host journal owner.
    WakeRead {
        /// Digest of the exact request carrier answered.
        request_sha256: String,
        /// Fence observed by the Host owner.
        state_fence: StateFence,
        /// Persisted wake intent and record checksum.
        readback: UserAutomationWakeReadback,
    },
    /// Closed Host-owner failure projection.
    Failed {
        /// Digest of the exact request carrier answered.
        request_sha256: String,
        /// Fence observed while producing the failure projection.
        state_fence: StateFence,
        /// Typed failure class; no success is inferred from an error response.
        failure: UserAutomationHostExecutionFailure,
    },
}

impl UserAutomationHostExecutionResponse {
    /// Builds a failure response bound to the exact request carrier.
    #[must_use]
    pub fn failed_for(
        request: &UserAutomationHostExecutionRequest,
        error: UserAutomationRuntimeError,
    ) -> Self {
        Self::Failed {
            request_sha256: request.request_sha256.clone(),
            state_fence: request.channel.state_fence.clone(),
            failure: UserAutomationHostExecutionFailure::from_runtime_error(error),
        }
    }

    /// Validates one response against its exact carrier and operation.
    pub fn validate_for(
        &self,
        request: &UserAutomationHostExecutionRequest,
    ) -> Result<(), UserAutomationRuntimeError> {
        request.validate()?;
        let (request_sha256, state_fence) = match self {
            Self::Admitted {
                request_sha256,
                state_fence,
                ..
            }
            | Self::Cancelled {
                request_sha256,
                state_fence,
                ..
            }
            | Self::WakeRead {
                request_sha256,
                state_fence,
                ..
            } => (request_sha256, state_fence),
            Self::Failed {
                request_sha256,
                state_fence,
                failure,
            } => {
                failure.validate()?;
                (request_sha256, state_fence)
            }
        };
        if request_sha256 != &request.request_sha256 || state_fence != request.state_fence() {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        match (&request.operation, self) {
            (
                UserAutomationHostExecutionOperation::AdmitOccurrence { request },
                Self::Admitted { execution, .. },
            ) => {
                let occurrence_id = request
                    .invocation
                    .occurrence_identity()
                    .map_err(|error| rejected(format!("occurrence identity: {error}")))?;
                execution
                    .validate()
                    .map_err(|error| rejected(format!("execution reference: {error}")))?;
                // `AutomationExecutionReference` has no fence field.  The
                // carrier fence above is the response fence; the stable
                // occurrence projection is checked here.
                if execution.occurrence_id != occurrence_id {
                    return Err(UserAutomationRuntimeError::IdentityConflict);
                }
                Ok(())
            }
            (
                UserAutomationHostExecutionOperation::CancelPendingWakes { .. },
                Self::Cancelled { wake_ids, .. },
            ) => validate_unique_text(wake_ids),
            (
                UserAutomationHostExecutionOperation::ReadPendingWake { request },
                Self::WakeRead { readback, .. },
            ) => readback
                .validate_for(request)
                .map_err(|_| UserAutomationRuntimeError::IdentityConflict),
            (_, Self::Failed { .. }) => Ok(()),
            (
                UserAutomationHostExecutionOperation::AdmitOccurrence { .. },
                Self::Cancelled { .. },
            )
            | (
                UserAutomationHostExecutionOperation::AdmitOccurrence { .. },
                Self::WakeRead { .. },
            )
            | (
                UserAutomationHostExecutionOperation::CancelPendingWakes { .. },
                Self::Admitted { .. },
            )
            | (
                UserAutomationHostExecutionOperation::CancelPendingWakes { .. },
                Self::WakeRead { .. },
            )
            | (
                UserAutomationHostExecutionOperation::ReadPendingWake { .. },
                Self::Admitted { .. },
            )
            | (
                UserAutomationHostExecutionOperation::ReadPendingWake { .. },
                Self::Cancelled { .. },
            ) => Err(UserAutomationRuntimeError::IdentityConflict),
        }
    }
}

/// Returns the metadata that binds the protocol frame to the typed carrier.
fn request_context(request: &UserAutomationHostExecutionRequest) -> &RequestMetadata {
    match &request.operation {
        UserAutomationHostExecutionOperation::AdmitOccurrence { request } => &request.context,
        UserAutomationHostExecutionOperation::CancelPendingWakes { request } => &request.context,
        UserAutomationHostExecutionOperation::ReadPendingWake { request } => &request.context,
    }
}

fn frame_identity(
    request: &UserAutomationHostExecutionRequest,
) -> Result<(RequestId, RequestIdentity), UserAutomationRuntimeError> {
    let request_id = RequestId::new(request.request_sha256.clone())
        .map_err(|_| rejected("UserAutomation frame request identity is invalid"))?;
    let mut metadata = request_context(request).clone();
    metadata.request_id = request_id.clone();
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: request.channel.state_fence.clone(),
        },
        idempotency_key: request.request_sha256.clone(),
        deadline_unix_ms: u64::MAX,
        cancellation_id: request.request_sha256.clone(),
    };
    identity
        .validate()
        .map_err(|_| rejected("UserAutomation frame identity is invalid"))?;
    Ok((request_id, identity))
}

fn frame_trace_context() -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([(
        USER_AUTOMATION_HOST_EXECUTION_TRACE_KEY.to_owned(),
        USER_AUTOMATION_HOST_EXECUTION_TRACE_VALUE.to_owned(),
    )])
}

fn validate_frame_trace_context(frame: &Frame) -> Result<(), UserAutomationRuntimeError> {
    if frame.trace_context.len() != 1
        || frame
            .trace_context
            .get(USER_AUTOMATION_HOST_EXECUTION_TRACE_KEY)
            .map(String::as_str)
            != Some(USER_AUTOMATION_HOST_EXECUTION_TRACE_VALUE)
    {
        return Err(rejected(
            "UserAutomation frame trace discriminator is invalid",
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAutomationHostExecutionOpenRequest {
    wire_id: String,
    wire_version: u16,
    open_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAutomationHostExecutionOpenResponse {
    wire_id: String,
    wire_version: u16,
    open_id: String,
    channel: UserAutomationHostChannelBinding,
}

fn open_trace_context() -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([(
        USER_AUTOMATION_HOST_EXECUTION_OPEN_TRACE_KEY.to_owned(),
        USER_AUTOMATION_HOST_EXECUTION_OPEN_TRACE_VALUE.to_owned(),
    )])
}

fn validate_open_trace_context(frame: &Frame) -> Result<(), UserAutomationRuntimeError> {
    if frame.trace_context.len() != 1
        || frame
            .trace_context
            .get(USER_AUTOMATION_HOST_EXECUTION_OPEN_TRACE_KEY)
            .map(String::as_str)
            != Some(USER_AUTOMATION_HOST_EXECUTION_OPEN_TRACE_VALUE)
    {
        return Err(rejected(
            "UserAutomation Host open discriminator is invalid",
        ));
    }
    Ok(())
}

/// Builds the first, caller-identified-only open frame. The provisional
/// `open_id` is correlation data; the Host authoritatively replaces it with a
/// fresh connection binding after authenticating the pipe peer.
pub fn user_automation_host_execution_open_frame()
-> Result<(String, Frame), UserAutomationRuntimeError> {
    let nonce = USER_AUTOMATION_SESSION_NONCE.fetch_add(1, Ordering::Relaxed);
    let open_id = format!("ua-host-open:{}:{}", std::process::id(), nonce);
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: open_id.clone(),
        request_id: None,
        kind: FrameKind::Control,
        message_type: MessageType::Start,
        request_identity: None,
        payload: ProtocolPayload::Json(
            serde_json::to_value(UserAutomationHostExecutionOpenRequest {
                wire_id: USER_AUTOMATION_HOST_EXECUTION_WIRE_ID.to_owned(),
                wire_version: USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION,
                open_id: open_id.clone(),
            })
            .map_err(|_| rejected("UserAutomation Host open encoding failed"))?,
        ),
        trace_context: open_trace_context(),
    };
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation Host open frame is invalid"))?;
    Ok((open_id, frame))
}

/// Decodes the authenticated Host open request before any owner queue access.
pub fn decode_user_automation_host_execution_open_frame(
    frame: &Frame,
) -> Result<String, UserAutomationRuntimeError> {
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation Host open frame is invalid"))?;
    validate_open_trace_context(frame)?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Start {
        return Err(rejected("UserAutomation Host open frame kind is invalid"));
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(rejected("UserAutomation Host open payload is invalid"));
    };
    let open: UserAutomationHostExecutionOpenRequest = serde_json::from_value(payload.clone())
        .map_err(|_| rejected("UserAutomation Host open payload is undecodable"))?;
    if open.wire_id != USER_AUTOMATION_HOST_EXECUTION_WIRE_ID
        || open.wire_version != USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION
        || open.open_id != frame.connection_id
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    validate_text(&open.open_id, "open_id")?;
    Ok(open.open_id)
}

/// Serializes the server-authored channel returned by the Host open owner.
pub fn user_automation_host_execution_open_response_frame(
    open_id: &str,
    channel: &UserAutomationHostChannelBinding,
) -> Result<Frame, UserAutomationRuntimeError> {
    validate_text(open_id, "open_id")?;
    channel.validate()?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: channel.connection_id.clone(),
        request_id: None,
        kind: FrameKind::Control,
        message_type: MessageType::Ready,
        request_identity: None,
        payload: ProtocolPayload::Json(
            serde_json::to_value(UserAutomationHostExecutionOpenResponse {
                wire_id: USER_AUTOMATION_HOST_EXECUTION_WIRE_ID.to_owned(),
                wire_version: USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION,
                open_id: open_id.to_owned(),
                channel: channel.clone(),
            })
            .map_err(|_| rejected("UserAutomation Host open response encoding failed"))?,
        ),
        trace_context: open_trace_context(),
    };
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation Host open response frame is invalid"))?;
    Ok(frame)
}

/// Decodes and validates the server-authored channel from the Host open reply.
pub fn decode_user_automation_host_execution_open_response_frame(
    frame: &Frame,
    open_id: &str,
) -> Result<UserAutomationHostChannelBinding, UserAutomationRuntimeError> {
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation Host open response is invalid"))?;
    validate_open_trace_context(frame)?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Ready {
        return Err(rejected(
            "UserAutomation Host open response kind is invalid",
        ));
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(rejected(
            "UserAutomation Host open response payload is invalid",
        ));
    };
    let response: UserAutomationHostExecutionOpenResponse = serde_json::from_value(payload.clone())
        .map_err(|_| rejected("UserAutomation Host open response is undecodable"))?;
    if response.wire_id != USER_AUTOMATION_HOST_EXECUTION_WIRE_ID
        || response.wire_version != USER_AUTOMATION_HOST_EXECUTION_WIRE_VERSION
        || response.open_id != open_id
        || frame.connection_id != response.channel.connection_id
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    response.channel.validate()?;
    Ok(response.channel)
}

/// Serializes one typed UserAutomation request into an authenticated EBP
/// frame. The frame identity is derived from the carrier digest and the
/// carrier's existing metadata/fence; no authority is minted here.
pub fn user_automation_host_execution_request_frame(
    request: &UserAutomationHostExecutionRequest,
) -> Result<Frame, UserAutomationRuntimeError> {
    request.validate()?;
    let (request_id, request_identity) = frame_identity(request)?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: request.channel.connection_id.clone(),
        request_id: Some(request_id),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(request)
                .map_err(|_| rejected("UserAutomation request encoding failed"))?,
        ),
        trace_context: frame_trace_context(),
    };
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation request frame is invalid"))?;
    Ok(frame)
}

/// Decodes and validates one typed UserAutomation request frame.
pub fn decode_user_automation_host_execution_request_frame(
    frame: &Frame,
) -> Result<UserAutomationHostExecutionRequest, UserAutomationRuntimeError> {
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation request frame is invalid"))?;
    validate_frame_trace_context(frame)?;
    if frame.kind != FrameKind::Request || frame.message_type != MessageType::Execute {
        return Err(rejected("UserAutomation request frame kind is invalid"));
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(rejected("UserAutomation request frame payload is invalid"));
    };
    let request: UserAutomationHostExecutionRequest = serde_json::from_value(payload.clone())
        .map_err(|_| rejected("UserAutomation request payload is undecodable"))?;
    request.validate()?;
    if frame.connection_id != request.channel.connection_id {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| rejected("UserAutomation request frame has no request id"))?;
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| rejected("UserAutomation request frame has no identity"))?;
    if frame_request_id.as_str() != request.request_sha256
        || identity.request.metadata.request_id != *frame_request_id
        || identity.request.state_fence != request.channel.state_fence
        || identity.idempotency_key != request.request_sha256
        || identity.cancellation_id != request.request_sha256
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    Ok(request)
}

/// Serializes one response against the exact request it answers.
pub fn user_automation_host_execution_response_frame(
    request: &UserAutomationHostExecutionRequest,
    response: &UserAutomationHostExecutionResponse,
) -> Result<Frame, UserAutomationRuntimeError> {
    response.validate_for(request)?;
    let (request_id, request_identity) = frame_identity(request)?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: request.channel.connection_id.clone(),
        request_id: Some(request_id),
        kind: FrameKind::Response,
        message_type: MessageType::Result,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(response)
                .map_err(|_| rejected("UserAutomation response encoding failed"))?,
        ),
        trace_context: frame_trace_context(),
    };
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation response frame is invalid"))?;
    Ok(frame)
}

/// Decodes one response and binds it to the exact request carrier.
pub fn decode_user_automation_host_execution_response_frame(
    frame: &Frame,
    request: &UserAutomationHostExecutionRequest,
) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError> {
    frame
        .validate()
        .map_err(|_| rejected("UserAutomation response frame is invalid"))?;
    validate_frame_trace_context(frame)?;
    if frame.kind != FrameKind::Response || frame.message_type != MessageType::Result {
        return Err(rejected("UserAutomation response frame kind is invalid"));
    }
    if frame.connection_id != request.channel.connection_id {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(rejected("UserAutomation response frame payload is invalid"));
    };
    let response: UserAutomationHostExecutionResponse = serde_json::from_value(payload.clone())
        .map_err(|_| rejected("UserAutomation response payload is undecodable"))?;
    response.validate_for(request)?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| rejected("UserAutomation response frame has no request id"))?;
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| rejected("UserAutomation response frame has no identity"))?;
    if frame_request_id.as_str() != request.request_sha256
        || identity.request.metadata.request_id != *frame_request_id
        || identity.request.state_fence != request.channel.state_fence
        || identity.idempotency_key != request.request_sha256
        || identity.cancellation_id != request.request_sha256
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    Ok(response)
}

/// Authenticated typed transport used by the Kernel execution client.
///
/// Implementations are composed from the existing authenticated Kernel-to-Host
/// channel.  They must reject an unauthenticated peer before invoking the Host
/// endpoint and must preserve unknown transport outcomes as
/// [`UserAutomationRuntimeError::UnknownOutcome`].
#[allow(async_fn_in_trait)]
pub trait UserAutomationHostExecutionTransport: Send + Sync {
    /// Returns the exact channel evidence retained after authentication.
    fn channel_binding(&self) -> &UserAutomationHostChannelBinding;

    /// Sends one typed carrier to the authenticated Host endpoint.
    async fn execute(
        &self,
        request: UserAutomationHostExecutionRequest,
    ) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError>;
}

/// Concrete Windows transport for the authenticated Kernel-to-Host execution
/// route. The named pipe remains the only transport owner; the mutex only
/// serializes request/response frames on one connection.
#[cfg(windows)]
pub struct AuthenticatedUserAutomationHostExecutionTransport {
    channel: UserAutomationHostChannelBinding,
    transport: tokio::sync::Mutex<NamedPipeTransport>,
    limits: TransportLimits,
}

#[cfg(windows)]
impl AuthenticatedUserAutomationHostExecutionTransport {
    /// Composes the transport from an already-connected, authenticated pipe
    /// and the server-authored channel returned by [`Self::open_channel`].
    /// Callers that need a fresh dial use [`Self::connect_server_authored`],
    /// which applies the same builtin-administrators peer expectation.
    pub fn new(
        channel: UserAutomationHostChannelBinding,
        transport: NamedPipeTransport,
    ) -> Result<Self, UserAutomationRuntimeError> {
        channel.validate()?;
        Ok(Self {
            channel,
            transport: tokio::sync::Mutex::new(transport),
            limits: TransportLimits::default(),
        })
    }

    /// Dials the authenticated Host pipe with the builtin-administrators peer
    /// expectation and returns the transport bound to the server-authored
    /// channel from the Host owner before any execution carrier is emitted.
    /// Ported from `codex/finish-a-20260922@ba5ec289`; the dial uses main's
    /// `NamedPipeTransport::connect_authenticated` with main's
    /// `NamedPipePeerExpectation::new_for_builtin_administrators`.
    pub async fn connect_server_authored(
        timeout: Duration,
    ) -> Result<Self, UserAutomationRuntimeError> {
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .map_err(|error| UserAutomationRuntimeError::Unavailable(error.to_string()))?;
        let mut transport = NamedPipeTransport::connect_authenticated(
            USER_AUTOMATION_HOST_EXECUTION_PIPE,
            timeout,
            &expectation,
        )
        .await
        .map_err(|error| UserAutomationRuntimeError::Unavailable(error.to_string()))?;
        let channel = Self::open_channel(&mut transport).await?;
        Self::new(channel, transport)
    }

    /// Performs the server-authored open handshake over an already-connected,
    /// authenticated transport and returns the complete channel binding from
    /// the Host owner before any execution carrier is emitted. The composer
    /// retains the expected State Fence check against the returned binding.
    pub async fn open_channel(
        transport: &mut NamedPipeTransport,
    ) -> Result<UserAutomationHostChannelBinding, UserAutomationRuntimeError> {
        let (open_id, open_frame) = user_automation_host_execution_open_frame()?;
        match transport
            .send_frame(&open_frame, TransportLimits::default())
            .await
            .map_err(|error| UserAutomationRuntimeError::UnknownOutcome(error.to_string()))?
        {
            DeliveryOutcome::Delivered => {}
            DeliveryOutcome::UnknownOutcome => {
                return Err(UserAutomationRuntimeError::UnknownOutcome(
                    "UserAutomation Host open delivery crossed an unknown boundary".to_owned(),
                ));
            }
        }
        let response_frame = transport
            .receive_frame(TransportLimits::default())
            .await
            .map_err(|error| UserAutomationRuntimeError::Unavailable(error.to_string()))?;
        decode_user_automation_host_execution_open_response_frame(&response_frame, &open_id)
    }

    /// Returns the transport-level bounds used for every frame.
    #[must_use]
    pub const fn limits(&self) -> TransportLimits {
        self.limits
    }
}

#[cfg(windows)]
#[allow(async_fn_in_trait)]
impl UserAutomationHostExecutionTransport for AuthenticatedUserAutomationHostExecutionTransport {
    fn channel_binding(&self) -> &UserAutomationHostChannelBinding {
        &self.channel
    }

    async fn execute(
        &self,
        request: UserAutomationHostExecutionRequest,
    ) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError> {
        if request.channel != self.channel {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let frame = user_automation_host_execution_request_frame(&request)?;
        let mut transport = self.transport.lock().await;
        let outcome = transport
            .send_frame(&frame, self.limits)
            .await
            .map_err(|error| UserAutomationRuntimeError::UnknownOutcome(error.to_string()))?;
        if outcome != DeliveryOutcome::Delivered {
            return Err(UserAutomationRuntimeError::UnknownOutcome(
                "UserAutomation request delivery crossed an unknown boundary".to_owned(),
            ));
        }
        let response_frame = transport
            .receive_frame(self.limits)
            .await
            .map_err(|error| UserAutomationRuntimeError::UnknownOutcome(error.to_string()))?;
        decode_user_automation_host_execution_response_frame(&response_frame, &request)
    }
}

/// Kernel-side client implementing both UserAutomation runtime owner ports.
pub struct UserAutomationHostExecutionClient<T> {
    transport: T,
}

impl<T> UserAutomationHostExecutionClient<T>
where
    T: UserAutomationHostExecutionTransport,
{
    /// Binds the client to one already authenticated Host channel.
    pub fn new(transport: T) -> Result<Self, UserAutomationRuntimeError> {
        transport.channel_binding().validate()?;
        Ok(Self { transport })
    }

    /// Returns the composed transport for root-owned channel integration.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    async fn execute(
        &self,
        request: UserAutomationHostExecutionRequest,
    ) -> Result<UserAutomationHostExecutionResponse, UserAutomationRuntimeError> {
        let response = self.transport.execute(request.clone()).await?;
        response.validate_for(&request)?;
        match response {
            UserAutomationHostExecutionResponse::Failed { failure, .. } => {
                Err(failure.into_runtime_error())
            }
            response => Ok(response),
        }
    }

    /// Reads one exact retained Pending wake through the authenticated
    /// transport. This is the durable-readback reconciliation path used after
    /// a lost response (`UnknownOutcome`): it never replays an owner effect.
    /// It mirrors the canonical wake-port readback contract; the owner trait
    /// method lives outside this slice, so the typed carrier path is bound
    /// here.
    pub async fn read_pending_wake(
        &self,
        request: impl Into<Box<UserAutomationWakeReadRequest>>,
    ) -> Result<UserAutomationWakeReadback, UserAutomationRuntimeError> {
        let carrier = UserAutomationHostExecutionRequest::read_pending_wake(
            self.transport.channel_binding().clone(),
            request,
        )?;
        match self.execute(carrier).await? {
            UserAutomationHostExecutionResponse::WakeRead { readback, .. } => Ok(readback),
            UserAutomationHostExecutionResponse::Admitted { .. }
            | UserAutomationHostExecutionResponse::Cancelled { .. } => {
                Err(UserAutomationRuntimeError::IdentityConflict)
            }
            UserAutomationHostExecutionResponse::Failed { failure, .. } => {
                Err(failure.into_runtime_error())
            }
        }
    }
}

impl<T> UserAutomationDurableJobPort for UserAutomationHostExecutionClient<T>
where
    T: UserAutomationHostExecutionTransport,
{
    async fn admit_occurrence(
        &self,
        request: impl Into<Box<UserAutomationRuntimeAdmission>>,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError> {
        let carrier = UserAutomationHostExecutionRequest::admit_occurrence(
            self.transport.channel_binding().clone(),
            request,
        )?;
        match self.execute(carrier).await? {
            UserAutomationHostExecutionResponse::Admitted { execution, .. } => Ok(execution),
            UserAutomationHostExecutionResponse::Cancelled { .. }
            | UserAutomationHostExecutionResponse::WakeRead { .. } => {
                Err(UserAutomationRuntimeError::IdentityConflict)
            }
            UserAutomationHostExecutionResponse::Failed { failure, .. } => {
                Err(failure.into_runtime_error())
            }
        }
    }
}

impl<T> UserAutomationWakePort for UserAutomationHostExecutionClient<T>
where
    T: UserAutomationHostExecutionTransport,
{
    async fn cancel_pending_wakes(
        &self,
        request: impl Into<Box<UserAutomationWakeCancellation>>,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        let carrier = UserAutomationHostExecutionRequest::cancel_pending_wakes(
            self.transport.channel_binding().clone(),
            request,
        )?;
        match self.execute(carrier).await? {
            UserAutomationHostExecutionResponse::Cancelled { wake_ids, .. } => Ok(wake_ids),
            UserAutomationHostExecutionResponse::Admitted { .. }
            | UserAutomationHostExecutionResponse::WakeRead { .. } => {
                Err(UserAutomationRuntimeError::IdentityConflict)
            }
            UserAutomationHostExecutionResponse::Failed { failure, .. } => {
                Err(failure.into_runtime_error())
            }
        }
    }
}

fn rejected(reason: impl Into<String>) -> UserAutomationRuntimeError {
    UserAutomationRuntimeError::Rejected(reason.into())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), UserAutomationRuntimeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(rejected(format!("{field} is invalid")));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), UserAutomationRuntimeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(rejected(format!("{field} must be lowercase sha256")));
    }
    Ok(())
}

fn validate_unique_text(values: &[String]) -> Result<(), UserAutomationRuntimeError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(value, "wake_id")?;
        if !unique.insert(value.as_str()) {
            return Err(rejected("duplicate wake cancellation identity"));
        }
    }
    Ok(())
}
