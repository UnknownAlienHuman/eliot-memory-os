//! Closed Kernel IPC for admitted Instrument verification-stage Blob streams.
//!
//! This protocol has its own profile-stage capability and deliberately does
//! not reuse the TestD process-stream identity. The caller names an admitted
//! profile/stage and the exact process binding; Kernel authenticates the
//! caller, rechecks current admission and owner facts, selects the current
//! fence, and retains every one-use call before forwarding it to Store.

use eliot_contracts::{StateFence, canonical_json_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::wire::{
    DurableStreamLocatorKind, ProcessStreamKind, ProcessStreamSinkBindingRef,
    ProcessStreamSinkWireResponse, ProcessStreamSourceReadbackResponse,
    PROCESS_STREAM_SINK_MAX_BODY_BYTES, PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES,
};

/// Selector for opening one authenticated profile-stage stream capability.
pub const VERIFICATION_STAGE_OPEN_WIRE_ID: &str = "eliot.kernel.verification-stage-open";
/// Selector for one retained profile-stage Blob operation.
pub const VERIFICATION_STAGE_CALL_WIRE_ID: &str = "eliot.kernel.verification-stage-call";
/// Selector for read-only reconciliation of one consumed operation token.
pub const VERIFICATION_STAGE_RECONCILE_WIRE_ID: &str =
    "eliot.kernel.verification-stage-reconcile";
/// Current revision for the closed profile-stage Blob IPC.
pub const VERIFICATION_STAGE_WIRE_REVISION: u16 = 1;
/// Maximum encoded profile-stage JSON IPC frame.
pub const VERIFICATION_STAGE_MAX_FRAME_BYTES: usize = 3 * 1024 * 1024;

/// Exact profile, stage, tool, argv, environment and source-root identity
/// admitted for one profile-stage launch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageBinding {
    /// Closed profile alias selected by the shared resolver.
    pub profile_id: String,
    /// Admitted profile revision.
    pub profile_revision: u64,
    /// Digest of the full admitted profile.
    pub profile_sha256: String,
    /// Digest of the admitted stage DAG.
    pub dag_sha256: String,
    /// Exact stage identity inside the admitted DAG.
    pub stage_id: String,
    /// Digest of the exact admitted stage record.
    pub stage_sha256: String,
    /// Digest of the executable that the stage is authorized to run.
    pub tool_sha256: String,
    /// Digest of the exact argv supplied to the process launch.
    pub argv_sha256: String,
    /// Digest of the exact non-secret environment projection.
    pub environment_sha256: String,
    /// Digest of the exact admitted source-root identity.
    pub source_root_identity_sha256: String,
}

impl VerificationStageBinding {
    /// Validates closed identities and their versioned profile/stage digests.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        validate_text("profile_id", &self.profile_id)?;
        validate_text("stage_id", &self.stage_id)?;
        if self.profile_id.len() > 128 || self.stage_id.len() > 128 {
            return Err(VerificationStageWireError::InvalidField("stage_identity"));
        }
        if self.profile_revision == 0 {
            return Err(VerificationStageWireError::InvalidField("profile_revision"));
        }
        for (field, value) in [
            ("profile_sha256", self.profile_sha256.as_str()),
            ("dag_sha256", self.dag_sha256.as_str()),
            ("stage_sha256", self.stage_sha256.as_str()),
            ("tool_sha256", self.tool_sha256.as_str()),
            ("argv_sha256", self.argv_sha256.as_str()),
            ("environment_sha256", self.environment_sha256.as_str()),
            (
                "source_root_identity_sha256",
                self.source_root_identity_sha256.as_str(),
            ),
        ] {
            validate_digest(field, value)?;
        }
        Ok(())
    }

    /// Deterministic digest over the complete admitted stage binding.
    pub fn digest(&self) -> Result<String, VerificationStageWireError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| VerificationStageWireError::InvalidField("stage_binding"))
    }
}

/// Runner request to open one profile-stage capability.
///
/// `process_binding_json` is the canonical serialization of the real
/// `ProcessExecutionBinding` emitted by the sealed launch request. It is
/// decoded and checked by Kernel against the authenticated stage admission;
/// it is not authority by itself. The request contains no caller-selected
/// fence, epoch, WorkScope, Policy, owner facts or source-admission receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageOpenRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact profile-stage/tool/source-root admission identity.
    pub binding: VerificationStageBinding,
    /// Canonical exact process binding emitted by the sealed launch request.
    pub process_binding_json: String,
    /// SHA-256 of the exact process-binding JSON bytes.
    pub process_binding_sha256: String,
    /// Request deadline in Unix milliseconds.
    pub deadline_ms: u64,
}

impl VerificationStageOpenRequest {
    /// Validates the closed selector and exact stage/process bindings.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_OPEN_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        self.binding.validate()?;
        validate_process_binding(
            &self.process_binding_json,
            &self.process_binding_sha256,
        )?;
        if self.deadline_ms == 0 {
            return Err(VerificationStageWireError::InvalidField("deadline_ms"));
        }
        validate_frame(self)
    }
}

/// Exact result of the authenticated Kernel stage-capability admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageOpenResponse {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact profile-stage identity submitted by the caller.
    pub binding: VerificationStageBinding,
    /// Exact process-binding digest submitted by the caller.
    pub process_binding_sha256: String,
    /// Kernel's current authenticated fence observed for this decision.
    pub state_fence: StateFence,
    /// Typed capability result.
    pub outcome: VerificationStageOpenOutcome,
}

impl VerificationStageOpenResponse {
    /// Validates the exact request echo and the granted capability.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageOpenRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        if self.wire_id != VERIFICATION_STAGE_OPEN_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
            || self.binding != request.binding
            || self.process_binding_sha256 != request.process_binding_sha256
        {
            return Err(VerificationStageWireError::InvalidField("open_response_binding"));
        }
        self.state_fence
            .validate()
            .map_err(|_| VerificationStageWireError::InvalidField("state_fence"))?;
        if let VerificationStageOpenOutcome::Granted { grant } = &self.outcome {
            grant.validate_for_request(request)?;
            if grant.state_fence != self.state_fence {
                return Err(VerificationStageWireError::InvalidField("grant_state_fence"));
            }
        }
        validate_frame(self)
    }
}

/// Closed capability result; an unavailable grant has no token or authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageOpenOutcome {
    /// Kernel retained a separate checked profile-stage capability.
    Granted {
        /// Exact profile-stage grant and first one-use token.
        grant: Box<VerificationStageGrant>,
    },
    /// Kernel refused admission before any Store effect.
    Unavailable {
        /// Closed non-sensitive refusal category.
        reason: VerificationStageUnavailableReason,
    },
}

/// Opaque Kernel-retained profile-stage capability reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageCapabilityRef {
    /// Bounded opaque lookup identity.
    pub reference: String,
}

impl VerificationStageCapabilityRef {
    /// Validates a bounded capability lookup reference.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        validate_text("capability_ref", &self.reference)?;
        if self.reference.len() > 128 {
            return Err(VerificationStageWireError::InvalidField("capability_ref"));
        }
        Ok(())
    }
}

/// One-use Kernel-issued operation token retained before any Store exchange.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageCallToken {
    /// Opaque Kernel-retained token reference.
    pub reference: String,
    /// Exact one-based operation ordinal.
    pub ordinal: u32,
}

impl VerificationStageCallToken {
    /// Validates the bounded one-use token.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        validate_text("call_token", &self.reference)?;
        if self.reference.len() > 128 || self.ordinal == 0 {
            return Err(VerificationStageWireError::InvalidField("call_token"));
        }
        Ok(())
    }
}

/// Kernel-issued grant for one exact admitted profile stage.
///
/// `state_fence` is selected by Kernel from the authenticated current session.
/// Its Authority Epoch is part of the fence and is independently checked on
/// every later call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageGrant {
    /// Exact granted profile-stage binding.
    pub binding: VerificationStageBinding,
    /// Opaque Kernel-retained call capability.
    pub capability: VerificationStageCapabilityRef,
    /// First one-use call token.
    pub first_call_token: VerificationStageCallToken,
    /// Exact launched process binding digest.
    pub process_binding_sha256: String,
    /// Current authenticated Kernel fence selected at grant time.
    pub state_fence: StateFence,
    /// Grant expiration in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

impl VerificationStageGrant {
    /// Validates a grant against the request it answers.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageOpenRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        self.binding.validate()?;
        if self.binding != request.binding
            || self.process_binding_sha256 != request.process_binding_sha256
            || self.expires_at_unix_ms < request.deadline_ms
        {
            return Err(VerificationStageWireError::InvalidField("grant_binding"));
        }
        self.capability.validate()?;
        self.first_call_token.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| VerificationStageWireError::InvalidField("state_fence"))?;
        validate_frame(self)
    }
}

/// Exact operation passed after a profile-stage grant. It deliberately omits
/// Store request identities, State Fences, owner facts and source-admission
/// proofs; Kernel creates those from retained authority and fresh owner reads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageOperationRequest {
    /// Open one stdout/stderr stream under the retained process binding.
    SinkOpen {
        /// Exact closed `ProcessStreamSinkOpenRequest` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Append a bounded byte chunk to one Store-retained stream.
    SinkAppend {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed `ProcessStreamSinkAppend` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Finalize one Store-retained stream under its original terminal identity.
    SinkFinalize {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed `ProcessStreamSinkFinalizeRequest` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Abort one Store-retained stream under its original terminal identity.
    SinkAbort {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed `ProcessStreamSinkAbortRequest` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Read the retained sink state without replaying an effect.
    SinkReadback {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Reconcile an uncertain original sink command without repeating it.
    SinkReconcile {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Exact original `ProcessStreamSinkUnknownOutcome` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Read one bounded chunk from the exact finalized immutable source.
    SourceReadback {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Stdout or stderr selected by the exact sink session.
        stream: ProcessStreamKind,
        /// Immutable source locator class from the finalized terminal.
        locator_kind: DurableStreamLocatorKind,
        /// Immutable source locator from the finalized terminal.
        locator: String,
        /// Owner-issued ready receipt reference from the finalized terminal.
        ready_receipt_ref: String,
        /// Whole-source SHA-256 from the finalized terminal.
        expected_sha256: String,
        /// Whole-source byte length from the finalized terminal.
        expected_byte_length: u64,
        /// Exact byte offset requested from the source.
        offset: u64,
        /// Caller size ceiling; never widens the fixed wire chunk bound.
        max_bytes: u64,
        /// Exact fixed chunk limit required by the Store readback contract.
        chunk_limit: u32,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
}

impl VerificationStageOperationRequest {
    /// Validates operation-specific identities and fixed bounds.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        let (binding, body, deadline_ms) = match self {
            Self::SinkOpen { body, deadline_ms } => (None, Some(body), *deadline_ms),
            Self::SinkAppend {
                binding,
                body,
                deadline_ms,
            }
            | Self::SinkFinalize {
                binding,
                body,
                deadline_ms,
            }
            | Self::SinkAbort {
                binding,
                body,
                deadline_ms,
            }
            | Self::SinkReconcile {
                binding,
                body,
                deadline_ms,
            } => (Some(binding), Some(body), *deadline_ms),
            Self::SinkReadback {
                binding,
                deadline_ms,
            } => (Some(binding), None, *deadline_ms),
            Self::SourceReadback {
                binding,
                locator,
                ready_receipt_ref,
                expected_sha256,
                expected_byte_length,
                offset,
                max_bytes,
                chunk_limit,
                deadline_ms,
                ..
            } => {
                binding
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("binding"))?;
                validate_text("locator", locator)?;
                validate_text("ready_receipt_ref", ready_receipt_ref)?;
                validate_digest("expected_sha256", expected_sha256)?;
                if *offset > *expected_byte_length
                    || *max_bytes < *expected_byte_length
                    || *chunk_limit != PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES
                {
                    return Err(VerificationStageWireError::InvalidField("source_range"));
                }
                (Some(binding), None, *deadline_ms)
            }
        };
        if let Some(binding) = binding {
            binding
                .validate()
                .map_err(|_| VerificationStageWireError::InvalidField("binding"))?;
        }
        if let Some(body) = body {
            let encoded = serde_json::to_vec(body)
                .map_err(|_| VerificationStageWireError::InvalidField("body"))?;
            if !body.is_object() || encoded.len() > PROCESS_STREAM_SINK_MAX_BODY_BYTES {
                return Err(VerificationStageWireError::InvalidField("body"));
            }
        }
        if deadline_ms == 0 {
            return Err(VerificationStageWireError::InvalidField("deadline_ms"));
        }
        Ok(())
    }
}

/// One-use operation sent over the authenticated existing Kernel front door.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageCallRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Opaque retained stage capability.
    pub capability: VerificationStageCapabilityRef,
    /// Exact one-use Kernel token.
    pub call_token: VerificationStageCallToken,
    /// Digest of the exact operation envelope below.
    pub operation_sha256: String,
    /// One exact semantic operation without caller-selected Kernel authority.
    pub operation: VerificationStageOperationRequest,
}

impl VerificationStageCallRequest {
    /// Validates the selector, token, operation and canonical operation digest.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_CALL_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        self.capability.validate()?;
        self.call_token.validate()?;
        self.operation.validate()?;
        let operation_json = canonical_json_bytes(&self.operation)
            .map_err(|_| VerificationStageWireError::InvalidField("operation"))?;
        if sha256_hex(&operation_json) != self.operation_sha256 {
            return Err(VerificationStageWireError::InvalidField("operation_sha256"));
        }
        validate_frame(self)
    }
}

/// Typed result returned after Kernel has retained the exact call outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageCallOutcome {
    /// Exact Store owner result was validated and retained by Kernel.
    Completed {
        /// Closed typed result for the matching operation family.
        result: VerificationStageStoreResult,
    },
    /// Kernel proves the exact original operation was never dispatched.
    NotStarted,
    /// Outcome is unresolved; caller must reconcile this exact token and digest.
    Unknown,
    /// Closed pre-effect refusal.
    Unavailable {
        /// Stable refusal category, with no provider prose.
        reason: VerificationStageUnavailableReason,
    },
}

/// Exact Store-side result family wrapped by the Kernel response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageStoreResult {
    /// Process-stream sink result.
    Sink {
        /// Closed Store owner response.
        response: ProcessStreamSinkWireResponse,
    },
    /// Immutable source readback result.
    SourceReadback {
        /// Closed Store owner response, including fresh owner readback proof.
        response: ProcessStreamSourceReadbackResponse,
    },
}

/// Kernel response bound to the exact admitted call and current fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageCallResponse {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact capability that admitted the operation.
    pub capability: VerificationStageCapabilityRef,
    /// Exact one-use token consumed by this response.
    pub call_token: VerificationStageCallToken,
    /// Exact original operation digest.
    pub operation_sha256: String,
    /// Kernel current fence observed for the response.
    pub state_fence: StateFence,
    /// Successor token when this outcome safely advanced the stream sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_call_token: Option<VerificationStageCallToken>,
    /// Retained typed result.
    pub outcome: VerificationStageCallOutcome,
}

impl VerificationStageCallResponse {
    /// Validates the response against the exact original request.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageCallRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        if self.wire_id != VERIFICATION_STAGE_CALL_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
            || self.capability != request.capability
            || self.call_token != request.call_token
            || self.operation_sha256 != request.operation_sha256
        {
            return Err(VerificationStageWireError::InvalidField("response_binding"));
        }
        self.state_fence
            .validate()
            .map_err(|_| VerificationStageWireError::InvalidField("state_fence"))?;
        if let Some(token) = &self.successor_call_token {
            token.validate()?;
            if token.ordinal != request.call_token.ordinal.saturating_add(1) {
                return Err(VerificationStageWireError::InvalidField("successor_call_token"));
            }
        }
        match &self.outcome {
            VerificationStageCallOutcome::Completed { result } => {
                result.validate_for_operation(&request.operation)?;
                if self.successor_call_token.is_none() {
                    return Err(VerificationStageWireError::InvalidField("successor_call_token"));
                }
            }
            VerificationStageCallOutcome::NotStarted
            | VerificationStageCallOutcome::Unknown
            | VerificationStageCallOutcome::Unavailable { .. }
                if self.successor_call_token.is_some() =>
            {
                return Err(VerificationStageWireError::InvalidField("successor_call_token"));
            }
            VerificationStageCallOutcome::NotStarted
            | VerificationStageCallOutcome::Unknown
            | VerificationStageCallOutcome::Unavailable { .. } => {}
        }
        validate_frame(self)
    }
}

impl VerificationStageStoreResult {
    fn validate_for_operation(
        &self,
        operation: &VerificationStageOperationRequest,
    ) -> Result<(), VerificationStageWireError> {
        match (operation, self) {
            (VerificationStageOperationRequest::SourceReadback { .. }, Self::SourceReadback { response }) => response
                .validate()
                .map_err(|_| VerificationStageWireError::InvalidField("source_readback")),
            (VerificationStageOperationRequest::SourceReadback { .. }, Self::Sink { .. })
            | (VerificationStageOperationRequest::SinkOpen { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkAppend { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkFinalize { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkAbort { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkReadback { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkReconcile { .. }, Self::SourceReadback { .. }) => {
                Err(VerificationStageWireError::InvalidField("result_operation"))
            }
            (VerificationStageOperationRequest::SinkOpen { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::Opened { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkAppend { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::AppendDisposition { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkFinalize { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::Finalized { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkAbort { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::Aborted { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkReadback { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::Readback { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkReconcile { .. }, Self::Sink { response })
                if matches!(
                    response,
                    ProcessStreamSinkWireResponse::Opened { .. }
                        | ProcessStreamSinkWireResponse::AppendDisposition { .. }
                        | ProcessStreamSinkWireResponse::Finalized { .. }
                        | ProcessStreamSinkWireResponse::Aborted { .. }
                        | ProcessStreamSinkWireResponse::Readback { .. }
                ) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (_, Self::Sink { .. }) => {
                Err(VerificationStageWireError::InvalidField("result_operation"))
            }
        }
    }
}

/// Read-only reconciliation query for a consumed call token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageReconcileRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Original retained capability.
    pub capability: VerificationStageCapabilityRef,
    /// Exact consumed one-use token.
    pub call_token: VerificationStageCallToken,
    /// Digest of the exact original operation.
    pub operation_sha256: String,
}

impl VerificationStageReconcileRequest {
    /// Validates a no-effect reconciliation request.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_RECONCILE_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        self.capability.validate()?;
        self.call_token.validate()?;
        validate_digest("operation_sha256", &self.operation_sha256)?;
        validate_frame(self)
    }
}

/// Closed non-sensitive pre-effect refusal categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStageUnavailableReason {
    AdmissionMissing,
    ProfileBindingMismatch,
    ProcessBindingMismatch,
    OwnerFactsUnavailable,
    StaleFence,
    StaleCapability,
    Capacity,
    StoreUnavailable,
    RequestRejected,
}

/// Typed validation failures for the closed profile-stage IPC.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VerificationStageWireError {
    /// Selector revision or wire ID is not admitted.
    #[error("unsupported verification-stage IPC revision")]
    UnsupportedRevision,
    /// A closed field failed validation.
    #[error("invalid verification-stage IPC field: {0}")]
    InvalidField(&'static str),
}

fn validate_text(field: &'static str, value: &str) -> Result<(), VerificationStageWireError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(VerificationStageWireError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), VerificationStageWireError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(VerificationStageWireError::InvalidField(field));
    }
    Ok(())
}

fn validate_process_binding(
    json: &str,
    digest: &str,
) -> Result<(), VerificationStageWireError> {
    validate_digest("process_binding_sha256", digest)?;
    let parsed: serde_json::Value =
        serde_json::from_str(json).map_err(|_| VerificationStageWireError::InvalidField("process_binding"))?;
    if !parsed.is_object()
        || json.len() > 16 * 1024
        || canonical_json_bytes(&parsed)
            .map(|bytes| String::from_utf8(bytes).ok())
            .ok()
            .flatten()
            .as_deref()
            != Some(json)
        || sha256_hex(json.as_bytes()) != digest
    {
        return Err(VerificationStageWireError::InvalidField("process_binding"));
    }
    Ok(())
}

fn validate_frame<T: Serialize>(value: &T) -> Result<(), VerificationStageWireError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|_| VerificationStageWireError::InvalidField("frame"))?;
    if encoded.len() > VERIFICATION_STAGE_MAX_FRAME_BYTES {
        return Err(VerificationStageWireError::InvalidField("frame"));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> VerificationStageBinding {
        VerificationStageBinding {
            profile_id: "package-verification-compile-only".to_owned(),
            profile_revision: 1,
            profile_sha256: "a".repeat(64),
            dag_sha256: "b".repeat(64),
            stage_id: "package-compile".to_owned(),
            stage_sha256: "c".repeat(64),
            tool_sha256: "d".repeat(64),
            argv_sha256: "e".repeat(64),
            environment_sha256: "f".repeat(64),
            source_root_identity_sha256: "0".repeat(64),
        }
    }

    #[test]
    fn verification_stage_open_accepts_exact_canonical_process_binding() {
        let process_binding = serde_json::json!({
            "operation_id": "stage-op-1",
            "process_tree_id": "stage-tree-1"
        });
        let process_binding_json = String::from_utf8(
            canonical_json_bytes(&process_binding).expect("canonical process binding"),
        )
        .expect("UTF-8 canonical process binding");
        let request = VerificationStageOpenRequest {
            wire_id: VERIFICATION_STAGE_OPEN_WIRE_ID.to_owned(),
            wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
            binding: binding(),
            process_binding_sha256: sha256_hex(process_binding_json.as_bytes()),
            process_binding_json,
            deadline_ms: 1_800_000_000_000,
        };

        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn verification_stage_open_refuses_a_process_binding_digest_mismatch() {
        let process_binding_json = "{\"operation_id\":\"stage-op-1\"}".to_owned();
        let request = VerificationStageOpenRequest {
            wire_id: VERIFICATION_STAGE_OPEN_WIRE_ID.to_owned(),
            wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
            binding: binding(),
            process_binding_json,
            process_binding_sha256: "1".repeat(64),
            deadline_ms: 1_800_000_000_000,
        };

        assert_eq!(
            request.validate(),
            Err(VerificationStageWireError::InvalidField("process_binding"))
        );
    }

    #[test]
    fn verification_stage_open_refuses_an_unbound_stage_digest() {
        let process_binding_json = "{\"operation_id\":\"stage-op-1\"}".to_owned();
        let mut stage = binding();
        stage.stage_sha256 = "not-a-digest".to_owned();
        let request = VerificationStageOpenRequest {
            wire_id: VERIFICATION_STAGE_OPEN_WIRE_ID.to_owned(),
            wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
            binding: stage,
            process_binding_sha256: sha256_hex(process_binding_json.as_bytes()),
            process_binding_json,
            deadline_ms: 1_800_000_000_000,
        };

        assert_eq!(
            request.validate(),
            Err(VerificationStageWireError::InvalidField("stage_sha256"))
        );
    }
}
