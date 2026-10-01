//! Closed EBP payloads for authenticated process-stream source readback.
//!
//! These semantic records intentionally carry no Blob lease, receipt context,
//! stage context, filesystem path, or caller-issued receipt. The Store binds
//! each request to the owner-retained stream session before consulting Blob.

use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire revision for the authenticated Store-to-Blob readback exchange.
pub const PROCESS_STREAM_READBACK_WIRE_REVISION: u16 = 1;
/// Maximum raw bytes carried by one JSON EBP source-readback response.
///
/// JSON encodes each byte as a decimal integer, so the frame cost can exceed
/// the source size. This bound stays well below EBP's 4 MiB frame ceiling.
pub const PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES: u32 = 256 * 1024;
/// Wire revision for the closed process-stream sink operations.
pub const PROCESS_STREAM_SINK_WIRE_REVISION: u16 = 1;
/// Maximum encoded body carried by one sink-operation frame.
pub const PROCESS_STREAM_SINK_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Closed EBP selector for the distinct owner-bound process-stream channel.
pub const BLOB_PROCESS_STREAM_WIRE_ID: &str = "eliot.blob.process-stream";
/// Dedicated negotiated EBP capability for the process-stream Blob channel.
pub const BLOB_PROCESS_STREAM_CAPABILITY: &str = "blob.process-stream";
/// Current revision for the distinct process-stream EBP channel.
pub const BLOB_PROCESS_STREAM_WIRE_REVISION: u16 = 1;
/// Bound for one encoded Blob process-stream JSON payload.
pub const BLOB_PROCESS_STREAM_MAX_FRAME_BYTES: usize = 3 * 1024 * 1024;
/// Narrow TestD-to-Kernel capability exchange selector. This frame is
/// authenticated by the established Kernel session and is accepted before
/// ordinary request-identity decoding only for the exact TestD peer role.
pub const BLOB_PROCESS_STREAM_KERNEL_WIRE_ID: &str = "eliot.kernel.blob-process-stream";
/// Current revision for the narrow TestD-to-Kernel capability exchange.
pub const BLOB_PROCESS_STREAM_KERNEL_WIRE_REVISION: u16 = 1;
/// Maximum encoded Kernel capability-exchange frame.
pub const BLOB_PROCESS_STREAM_KERNEL_MAX_FRAME_BYTES: usize = 3 * 1024 * 1024;

/// Operation tag inside the distinct Blob EBP channel.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum BlobProcessStreamOperationRequest {
    /// Process stream sink mutation/readback operation.
    Sink {
        /// Exact closed stream-sink request.
        request: ProcessStreamSinkWireRequest,
    },
    /// Immutable source readback chunk operation.
    SourceReadback {
        /// Exact closed source readback request.
        request: ProcessStreamSourceReadbackRequest,
    },
}

/// Closed semantic request on the dedicated Blob EBP path.
///
/// The Store receiver recognizes this exact `wire_id` before attempting the
/// canonical `StoreRequest` decode. Blob bytes and sink commands never enter
/// the canonical Store request vocabulary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessStreamFrameRequest {
    /// Closed operation family selector.
    pub wire_id: String,
    /// Wire revision.
    pub wire_revision: u16,
    /// Exact operation-specific body.
    pub operation: BlobProcessStreamOperationRequest,
}

impl BlobProcessStreamFrameRequest {
    /// Validates the closed selector, revision, and exact operation body.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        if self.wire_id != BLOB_PROCESS_STREAM_WIRE_ID
            || self.wire_revision != BLOB_PROCESS_STREAM_WIRE_REVISION
        {
            return Err(WireValidationError::UnsupportedRevision);
        }
        let encoded_len = serde_json::to_vec(self)
            .map_err(|_| WireValidationError::InvalidField("frame"))?
            .len();
        if encoded_len > BLOB_PROCESS_STREAM_MAX_FRAME_BYTES {
            return Err(WireValidationError::InvalidField("frame"));
        }
        match &self.operation {
            BlobProcessStreamOperationRequest::Sink { request } => request.validate(),
            BlobProcessStreamOperationRequest::SourceReadback { request } => request.validate(),
        }
    }
}

/// Operation tag inside a Blob EBP response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum BlobProcessStreamOperationResponse {
    /// Process stream sink operation result.
    Sink {
        /// Closed owner response.
        response: ProcessStreamSinkWireResponse,
    },
    /// Immutable source readback result.
    SourceReadback {
        /// Closed owner response.
        response: ProcessStreamSourceReadbackResponse,
    },
}

/// Closed semantic response on the dedicated Blob EBP path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessStreamFrameResponse {
    /// Closed operation family selector.
    pub wire_id: String,
    /// Wire revision.
    pub wire_revision: u16,
    /// Exact operation-specific result.
    pub operation: BlobProcessStreamOperationResponse,
}

impl BlobProcessStreamFrameResponse {
    /// Validates the closed selector and response frame size.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        if self.wire_id != BLOB_PROCESS_STREAM_WIRE_ID
            || self.wire_revision != BLOB_PROCESS_STREAM_WIRE_REVISION
        {
            return Err(WireValidationError::UnsupportedRevision);
        }
        let encoded_len = serde_json::to_vec(self)
            .map_err(|_| WireValidationError::InvalidField("frame"))?
            .len();
        if encoded_len > BLOB_PROCESS_STREAM_MAX_FRAME_BYTES {
            return Err(WireValidationError::InvalidField("frame"));
        }
        Ok(())
    }
}

/// One-use opaque call reference issued by Kernel for a retained process-stream
/// capability. The server binds it to an operation sequence and body digest;
/// the token contains no request identity or signing material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessStreamCallToken {
    /// Opaque, bounded lookup reference retained by Kernel.
    pub reference: String,
    /// Operation ordinal fixed by Kernel when the token is issued.
    pub ordinal: u32,
}

impl BlobProcessStreamCallToken {
    /// Validates the opaque reference and nonzero operation ordinal.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        if self.reference.trim().is_empty()
            || self.reference.len() > 128
            || self.reference.chars().any(char::is_control)
            || self.ordinal == 0
        {
            return Err(WireValidationError::InvalidField("call_token"));
        }
        Ok(())
    }
}

/// Narrow authenticated TestD-to-Kernel request for one Blob process-stream
/// operation. The established session supplies peer authentication; Kernel
/// resolves both references against its retained job capability and issues
/// the Store-facing RequestIdentity internally.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessStreamKernelRequest {
    /// Closed wire selector.
    pub wire_id: String,
    /// Closed wire revision.
    pub wire_revision: u16,
    /// Opaque Kernel-issued process-stream capability.
    pub capability: ProcessStreamSinkCapabilityRef,
    /// Opaque one-use Kernel-issued operation token.
    pub call_token: BlobProcessStreamCallToken,
    /// Digest of the exact typed operation envelope below.
    pub operation_sha256: String,
    /// Exact closed Blob process-stream operation.
    pub operation: BlobProcessStreamFrameRequest,
}

impl BlobProcessStreamKernelRequest {
    /// Constructs a narrow Kernel exchange with a digest over the exact
    /// typed operation envelope.
    pub fn new(
        capability: ProcessStreamSinkCapabilityRef,
        call_token: BlobProcessStreamCallToken,
        operation: BlobProcessStreamFrameRequest,
    ) -> Result<Self, WireValidationError> {
        let operation_bytes = serde_json::to_vec(&operation)
            .map_err(|_| WireValidationError::InvalidField("operation"))?;
        let request = Self {
            wire_id: BLOB_PROCESS_STREAM_KERNEL_WIRE_ID.to_owned(),
            wire_revision: BLOB_PROCESS_STREAM_KERNEL_WIRE_REVISION,
            capability,
            call_token,
            operation_sha256: sha256_hex(&operation_bytes),
            operation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates exact selectors, opaque references, body digest, and limits.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        if self.wire_id != BLOB_PROCESS_STREAM_KERNEL_WIRE_ID
            || self.wire_revision != BLOB_PROCESS_STREAM_KERNEL_WIRE_REVISION
        {
            return Err(WireValidationError::UnsupportedRevision);
        }
        self.capability.validate()?;
        self.call_token.validate()?;
        self.operation.validate()?;
        validate_digest("operation_sha256", &self.operation_sha256)?;
        let operation = serde_json::to_vec(&self.operation)
            .map_err(|_| WireValidationError::InvalidField("operation"))?;
        if sha256_hex(&operation) != self.operation_sha256 {
            return Err(WireValidationError::InvalidField("operation_sha256"));
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|_| WireValidationError::InvalidField("frame"))?;
        if encoded.len() > BLOB_PROCESS_STREAM_KERNEL_MAX_FRAME_BYTES {
            return Err(WireValidationError::InvalidField("frame"));
        }
        Ok(())
    }
}

/// Result of one narrow authenticated TestD-to-Kernel capability operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum BlobProcessStreamKernelOutcome {
    /// Exact typed owner response retained for this token and operation digest.
    Completed {
        /// Digest of the original operation body.
        operation_sha256: String,
        /// Exact closed Store/Blob result.
        response: BlobProcessStreamFrameResponse,
    },
    /// Kernel proved that the original token was reserved and no Store call began.
    NotStarted {
        /// Original operation digest.
        operation_sha256: String,
    },
    /// Kernel cannot prove whether the original Store call completed.
    Unknown {
        /// Original operation digest.
        operation_sha256: String,
    },
}

/// Closed response to [`BlobProcessStreamKernelRequest`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessStreamKernelResponse {
    /// Closed wire selector.
    pub wire_id: String,
    /// Closed wire revision.
    pub wire_revision: u16,
    /// Echo of the opaque capability reference.
    pub capability: ProcessStreamSinkCapabilityRef,
    /// Echo of the one-use token reference and ordinal.
    pub call_token: BlobProcessStreamCallToken,
    /// Retained outcome for this exact operation.
    pub outcome: BlobProcessStreamKernelOutcome,
}

impl BlobProcessStreamKernelResponse {
    /// Validates response selectors and bounded encoded size.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        if self.wire_id != BLOB_PROCESS_STREAM_KERNEL_WIRE_ID
            || self.wire_revision != BLOB_PROCESS_STREAM_KERNEL_WIRE_REVISION
        {
            return Err(WireValidationError::UnsupportedRevision);
        }
        self.capability.validate()?;
        self.call_token.validate()?;
        match &self.outcome {
            BlobProcessStreamKernelOutcome::Completed {
                operation_sha256,
                response,
            } => {
                validate_digest("operation_sha256", operation_sha256)?;
                response.validate()?;
            }
            BlobProcessStreamKernelOutcome::NotStarted { operation_sha256 }
            | BlobProcessStreamKernelOutcome::Unknown { operation_sha256 } => {
                validate_digest("operation_sha256", operation_sha256)?;
            }
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|_| WireValidationError::InvalidField("frame"))?;
        if encoded.len() > BLOB_PROCESS_STREAM_KERNEL_MAX_FRAME_BYTES {
            return Err(WireValidationError::InvalidField("frame"));
        }
        Ok(())
    }

    /// Validates that this response belongs to the exact request token and
    /// operation digest, preventing cross-token or stale result acceptance.
    pub fn validate_for_request(
        &self,
        request: &BlobProcessStreamKernelRequest,
    ) -> Result<(), WireValidationError> {
        self.validate()?;
        request.validate()?;
        if self.capability != request.capability || self.call_token != request.call_token {
            return Err(WireValidationError::InvalidField("response_binding"));
        }
        let operation_sha256 = match &self.outcome {
            BlobProcessStreamKernelOutcome::Completed {
                operation_sha256,
                ..
            }
            | BlobProcessStreamKernelOutcome::NotStarted { operation_sha256 }
            | BlobProcessStreamKernelOutcome::Unknown { operation_sha256 } => operation_sha256,
        };
        if operation_sha256 != &request.operation_sha256 {
            return Err(WireValidationError::InvalidField("response_operation_sha256"));
        }
        Ok(())
    }
}

/// Closed process-stream discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStreamKind {
    /// Captured process standard output.
    Stdout,
    /// Captured process standard error.
    Stderr,
}

/// Closed source-locator discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableStreamLocatorKind {
    /// Provider-neutral BlobStore object.
    Blob,
    /// Another admitted immutable artifact/evidence store.
    ImmutableArtifact,
}

/// Immutable policy binding carried by the readback caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamPolicyBinding {
    /// Governing policy snapshot/decision reference.
    pub policy_ref: String,
    /// Privacy classification/reference.
    pub privacy_ref: String,
    /// Visibility/disclosure reference.
    pub visibility_ref: String,
    /// Retention/erasure reference.
    pub retention_ref: String,
    /// Exact redaction/transformation profile reference.
    pub redaction_ref: String,
}

/// Semantic readback request sent over an already authenticated Store EBP session.
///
/// `operation_id`, `process_tree_id`, and `job_id` are the producer identity
/// used to find the retained owner binding. The Store uses the retained sink
/// session/terminal/open digests internally; clients cannot choose them here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSourceReadbackRequest {
    /// Wire revision, currently [`PROCESS_STREAM_READBACK_WIRE_REVISION`].
    pub wire_revision: u16,
    /// Durable job identity serving this readback.
    pub job_id: String,
    /// Instrument invocation identity serving this readback.
    pub invocation_id: String,
    /// Exact admitted operation identity.
    pub operation_id: String,
    /// Exact admitted process-tree identity.
    pub process_tree_id: String,
    /// Exact serialized `ProcessExecutionBinding` admitted for this source.
    pub process_binding_json: String,
    /// SHA-256 of the exact serialized process binding bytes.
    pub process_binding_sha256: String,
    /// Stdout or stderr.
    pub stream: ProcessStreamKind,
    /// Immutable locator class.
    pub locator_kind: DurableStreamLocatorKind,
    /// Immutable source locator value.
    pub locator: String,
    /// Owner-issued ready-receipt reference from admitted evidence.
    pub ready_receipt_ref: String,
    /// Expected SHA-256 over exact durable source bytes.
    pub expected_sha256: String,
    /// Expected source byte length.
    pub expected_byte_length: u64,
    /// Immutable policy/privacy/visibility/retention binding.
    pub policy: ProcessStreamPolicyBinding,
    /// Exact serialized policy bytes retained with the original staged source.
    pub policy_json: String,
    /// SHA-256 of the exact serialized policy bytes.
    pub policy_sha256: String,
    /// Exact state fence under which readback is admitted.
    pub fence: StateFence,
    /// Maximum source size accepted by the caller.
    pub max_bytes: u64,
    /// Byte offset requested from the exact immutable source.
    pub offset: u64,
    /// Maximum bytes in this response chunk; must equal the fixed wire bound.
    pub chunk_limit: u32,
    /// Unix-millisecond readback deadline.
    pub deadline_ms: u64,
}

impl ProcessStreamSourceReadbackRequest {
    /// Rejects incomplete, oversized, or malformed semantic requests.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        if self.wire_revision != PROCESS_STREAM_READBACK_WIRE_REVISION {
            return Err(WireValidationError::UnsupportedRevision);
        }
        for (field, value) in [
            ("job_id", self.job_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
            ("operation_id", self.operation_id.as_str()),
            ("process_tree_id", self.process_tree_id.as_str()),
            ("locator", self.locator.as_str()),
            ("ready_receipt_ref", self.ready_receipt_ref.as_str()),
        ] {
            validate_text(field, value)?;
        }
        validate_digest("expected_sha256", &self.expected_sha256)?;
        validate_digest("process_binding_sha256", &self.process_binding_sha256)?;
        validate_digest("policy_sha256", &self.policy_sha256)?;
        if self.process_binding_json.len() > 16 * 1024
            || self.policy_json.len() > 4 * 1024
            || !json_object(&self.process_binding_json)
            || sha256_hex(self.process_binding_json.as_bytes()) != self.process_binding_sha256
            || serde_json::to_string(&self.policy).ok().as_deref()
                != Some(self.policy_json.as_str())
            || sha256_hex(self.policy_json.as_bytes()) != self.policy_sha256
        {
            return Err(WireValidationError::InvalidField("process_binding"));
        }
        if self.max_bytes < self.expected_byte_length {
            return Err(WireValidationError::InvalidField("max_bytes"));
        }
        if self.offset > self.expected_byte_length
            || self.chunk_limit != PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES
        {
            return Err(WireValidationError::InvalidField("chunk"));
        }
        if self.deadline_ms == 0 {
            return Err(WireValidationError::InvalidField("deadline_ms"));
        }
        self.fence
            .validate()
            .map_err(|_| WireValidationError::InvalidField("fence"))?;
        for (field, value) in [
            ("policy_ref", self.policy.policy_ref.as_str()),
            ("privacy_ref", self.policy.privacy_ref.as_str()),
            ("visibility_ref", self.policy.visibility_ref.as_str()),
            ("retention_ref", self.policy.retention_ref.as_str()),
            ("redaction_ref", self.policy.redaction_ref.as_str()),
        ] {
            validate_text(field, value)?;
        }
        Ok(())
    }
}

/// Closed operation selector for the retained Store-side stream sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStreamSinkOperation {
    /// Bind one process stream and mint its retained owner context.
    Open,
    /// Append one bounded, digest-bound byte chunk.
    Append,
    /// Finalize the exact terminal command.
    Finalize,
    /// Abort the exact terminal command.
    Abort,
    /// Read the owner-retained sink observation.
    Readback,
    /// Reconcile the original uncertain terminal command.
    Reconcile,
}

/// Opaque reference to the Kernel-issued stream capability.
///
/// The reference selects a Kernel-retained admission. It grants no authority
/// by itself and is accepted only over the authenticated Kernel EBP peer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkCapabilityRef {
    /// Opaque Kernel-selected lookup identity.
    pub reference: String,
}

impl ProcessStreamSinkCapabilityRef {
    /// Validates a bounded opaque reference.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        if self.reference.trim().is_empty()
            || self.reference.len() > 128
            || self.reference.chars().any(char::is_control)
        {
            return Err(WireValidationError::InvalidField("capability_ref"));
        }
        Ok(())
    }
}

/// Exact identity of one retained open stream at the Store owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkBindingRef {
    /// Owner-bound sink session identity.
    pub session_id: String,
    /// Owner-bound source identity.
    pub source_id: String,
    /// Original terminal identity.
    pub terminal_id: String,
    /// Digest of the original validated Open request.
    pub open_request_sha256: String,
}

impl ProcessStreamSinkBindingRef {
    /// Validates exact bounded sink identities.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        validate_text("session_id", &self.session_id)?;
        validate_text("source_id", &self.source_id)?;
        validate_text("terminal_id", &self.terminal_id)?;
        validate_digest("open_request_sha256", &self.open_request_sha256)
    }
}

/// Closed Store EBP request family for process stream sink operations.
///
/// `body` is limited to the operation's already closed `eliot-process`
/// request wire. Kernel and Store adapters must deserialize it into exactly
/// the named request type with unknown-field rejection and call its validator
/// before using any field. No operation accepts arbitrary commands, paths,
/// Blob contexts, leases, or caller-issued receipts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProcessStreamSinkWireRequest {
    /// Open a stream from the admitted process binding.
    Open {
        /// Kernel-issued admitted process capability reference.
        capability: ProcessStreamSinkCapabilityRef,
        /// Exact closed ProcessStreamSinkOpenRequest JSON object.
        body: serde_json::Value,
        /// Authenticated request fence.
        fence: StateFence,
        /// Absolute Unix-millisecond operation deadline.
        deadline_ms: u64,
    },
    /// Append one exact sequence/offset chunk to its retained session.
    Append {
        /// Kernel-issued admitted process capability reference.
        capability: ProcessStreamSinkCapabilityRef,
        /// Exact retained stream binding selected by this caller.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed ProcessStreamSinkAppend JSON object.
        body: serde_json::Value,
        /// Authenticated request fence.
        fence: StateFence,
        /// Absolute Unix-millisecond operation deadline.
        deadline_ms: u64,
    },
    /// Finalize a stream under its exact terminal command identity.
    Finalize {
        /// Kernel-issued admitted process capability reference.
        capability: ProcessStreamSinkCapabilityRef,
        /// Exact retained stream binding selected by this caller.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed ProcessStreamSinkFinalizeRequest JSON object.
        body: serde_json::Value,
        /// Authenticated request fence.
        fence: StateFence,
        /// Absolute Unix-millisecond operation deadline.
        deadline_ms: u64,
    },
    /// Abort a stream under its exact terminal command identity.
    Abort {
        /// Kernel-issued admitted process capability reference.
        capability: ProcessStreamSinkCapabilityRef,
        /// Exact retained stream binding selected by this caller.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed ProcessStreamSinkAbortRequest JSON object.
        body: serde_json::Value,
        /// Authenticated request fence.
        fence: StateFence,
        /// Absolute Unix-millisecond operation deadline.
        deadline_ms: u64,
    },
    /// Read back the current retained sink observation, with no effect replay.
    Readback {
        /// Kernel-issued admitted process capability reference.
        capability: ProcessStreamSinkCapabilityRef,
        /// Exact retained stream binding selected by this caller.
        binding: ProcessStreamSinkBindingRef,
        /// Authenticated request fence.
        fence: StateFence,
        /// Absolute Unix-millisecond operation deadline.
        deadline_ms: u64,
    },
    /// Reconcile an uncertain original terminal command without repeating it.
    Reconcile {
        /// Kernel-issued admitted process capability reference.
        capability: ProcessStreamSinkCapabilityRef,
        /// Exact retained stream binding selected by this caller.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed ProcessStreamSinkUnknownOutcome JSON object.
        body: serde_json::Value,
        /// Authenticated request fence.
        fence: StateFence,
        /// Absolute Unix-millisecond operation deadline.
        deadline_ms: u64,
    },
}

impl ProcessStreamSinkWireRequest {
    /// Rejects invalid capability references, unbounded bodies, fences, and deadlines.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        let (capability, binding, body, fence, deadline_ms) = match self {
            Self::Open {
                capability,
                body,
                fence,
                deadline_ms,
            } => (capability, None, Some(body), fence, *deadline_ms),
            Self::Append {
                capability,
                binding,
                body,
                fence,
                deadline_ms,
            }
            | Self::Finalize {
                capability,
                binding,
                body,
                fence,
                deadline_ms,
            }
            | Self::Abort {
                capability,
                binding,
                body,
                fence,
                deadline_ms,
            }
            | Self::Reconcile {
                capability,
                binding,
                body,
                fence,
                deadline_ms,
            } => (capability, Some(binding), Some(body), fence, *deadline_ms),
            Self::Readback {
                capability,
                binding,
                fence,
                deadline_ms,
            } => (capability, Some(binding), None, fence, *deadline_ms),
        };
        capability.validate()?;
        if let Some(binding) = binding {
            binding.validate()?;
        }
        if let Some(body) = body {
            let encoded = serde_json::to_vec(body)
                .map_err(|_| WireValidationError::InvalidField("body"))?;
            if !body.is_object() || encoded.len() > PROCESS_STREAM_SINK_MAX_BODY_BYTES {
                return Err(WireValidationError::InvalidField("body"));
            }
        }
        if deadline_ms == 0 {
            return Err(WireValidationError::InvalidField("deadline_ms"));
        }
        fence
            .validate()
            .map_err(|_| WireValidationError::InvalidField("fence"))
    }
}

/// Closed owner outcomes for process-stream sink operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProcessStreamSinkWireResponse {
    /// Open accepted under the exact original binding.
    Opened {
        /// Store-retained stream binding.
        binding: ProcessStreamSinkBindingRef,
    },
    /// Append returned its exact typed disposition JSON.
    AppendDisposition {
        /// Closed ProcessStreamSinkAppendDisposition JSON.
        body: serde_json::Value,
    },
    /// Finalize returned owner-validated terminal evidence JSON.
    Finalized {
        /// Closed terminal projection JSON.
        body: serde_json::Value,
    },
    /// Abort returned owner-validated terminal evidence JSON.
    Aborted {
        /// Closed terminal projection JSON.
        body: serde_json::Value,
    },
    /// Readback returned the exact retained owner observation JSON.
    Readback {
        /// Closed ProcessStreamSinkReadback JSON.
        body: serde_json::Value,
    },
    /// Owner proved the exact original command never started.
    NotStarted,
    /// The exact original command outcome remains unknown.
    Unknown,
}

/// Closed outcome of a source readback/reconciliation request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProcessStreamSourceReadbackResponse {
    /// Exact ready source bytes plus owner-issued receipt evidence.
    Ready {
        /// Bounded ephemeral source bytes; clients must not persist this field.
        bytes: Vec<u8>,
        /// Offset of this contiguous chunk in the exact source.
        chunk_offset: u64,
        /// SHA-256 observed over the returned exact bytes.
        observed_sha256: String,
        /// Length observed over the returned exact bytes.
        observed_byte_length: u64,
        /// Original owner-issued ready-receipt reference.
        ready_receipt_ref: String,
        /// Store Blob owner generation that served the readback.
        source_owner_generation: u64,
        /// Owner-issued immutable-source readback receipt identity.
        readback_receipt_id: String,
        /// State fence observed by the owner at readback time.
        observed_fence: StateFence,
        /// Unix-millisecond time observed by the owner.
        observed_at_unix_ms: u64,
    },
    /// Exact original intent is durably reserved and no stage effect began.
    NotStarted,
    /// The original operation result cannot be determined safely.
    Unknown,
}

/// Shape and bounded-text error for this closed wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WireValidationError {
    /// Wire revision does not match the supported version.
    #[error("unsupported process-stream readback wire revision")]
    UnsupportedRevision,
    /// A field is missing, malformed, or outside its contract.
    #[error("invalid process-stream readback field: {0}")]
    InvalidField(&'static str),
}

fn validate_text(field: &'static str, value: &str) -> Result<(), WireValidationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(WireValidationError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), WireValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(WireValidationError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn json_object(value: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(value).is_ok_and(|value| value.is_object())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
