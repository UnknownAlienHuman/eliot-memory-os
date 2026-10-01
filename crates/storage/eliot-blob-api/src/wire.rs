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
/// Narrow `TestD`-to-Kernel capability exchange selector. This frame is
/// authenticated by the established Kernel session and is accepted before
/// ordinary request-identity decoding only for the exact `TestD` peer role.
pub const BLOB_PROCESS_STREAM_KERNEL_WIRE_ID: &str = "eliot.kernel.blob-process-stream";
/// Current revision for the narrow `TestD`-to-Kernel capability exchange.
pub const BLOB_PROCESS_STREAM_KERNEL_WIRE_REVISION: u16 = 1;
/// Maximum encoded Kernel capability-exchange frame.
pub const BLOB_PROCESS_STREAM_KERNEL_MAX_FRAME_BYTES: usize = 3 * 1024 * 1024;
/// Closed daemon owner-facts exchange requested by Kernel over its authenticated
/// `eliotd` session. This route returns proof references only, never Blob
/// leases or receipt contexts.
pub const BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_ID: &str =
    "eliot.kernel.blob-process-stream-owner-facts";
/// Current owner-facts exchange revision.
pub const BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_REVISION: u16 = 1;

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

/// Narrow authenticated `TestD`-to-Kernel request for one Blob process-stream
/// operation. The established session supplies peer authentication; Kernel
/// resolves both references against its retained job capability and issues
/// the Store-facing `RequestIdentity` and `StateFence` internally. Its operation
/// projection deliberately does not reuse the Store-facing request type,
/// because that type contains a fence which only Kernel may select.
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
    /// Exact closed semantic operation, without Store RequestIdentity or fence.
    pub operation: BlobProcessStreamKernelOperationRequest,
}

/// One closed semantic operation accepted from `TestD` by Kernel.
///
/// The operation-specific `body` is decoded by Kernel into the exact named
/// `eliot-process` type before grant lookup or owner dispatch. This API crate
/// intentionally has no dependency on `eliot-process`; a JSON body cannot
/// reach Store unless that typed decode and validation succeeds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum BlobProcessStreamKernelOperationRequest {
    /// Open one stream using an admitted process binding.
    SinkOpen {
        /// Exact ProcessStreamSinkOpenRequest object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Append one bounded stream chunk.
    SinkAppend {
        /// Exact owner-retained stream identity.
        binding: ProcessStreamSinkBindingRef,
        /// Exact ProcessStreamSinkAppendRequest object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Finalize one exact terminal command.
    SinkFinalize {
        /// Exact owner-retained stream identity.
        binding: ProcessStreamSinkBindingRef,
        /// Exact ProcessStreamSinkFinalizeRequest object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Abort one exact terminal command.
    SinkAbort {
        /// Exact owner-retained stream identity.
        binding: ProcessStreamSinkBindingRef,
        /// Exact ProcessStreamSinkAbortRequest object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Read the retained stream sink state.
    SinkReadback {
        /// Exact owner-retained stream identity.
        binding: ProcessStreamSinkBindingRef,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Reconcile an uncertain original terminal command.
    SinkReconcile {
        /// Exact owner-retained stream identity.
        binding: ProcessStreamSinkBindingRef,
        /// Exact ProcessStreamSinkUnknownOutcome object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Read one contiguous chunk from the original immutable source.
    SourceReadback {
        /// Semantic request. Kernel supplies the Store-side `StateFence`.
        request: BlobProcessStreamKernelSourceReadbackRequest,
    },
}

impl BlobProcessStreamKernelOperationRequest {
    /// Validates bounded envelope shape. The Kernel adapter performs the
    /// operation-specific `eliot-process` deserialization and validation.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        match self {
            Self::SinkOpen { body, deadline_ms }
            => {
                validate_body(body)?;
                if *deadline_ms == 0 {
                    return Err(WireValidationError::InvalidField("deadline_ms"));
                }
            }
            Self::SinkAppend { binding, body, deadline_ms }
            | Self::SinkFinalize { binding, body, deadline_ms }
            | Self::SinkAbort { binding, body, deadline_ms }
            | Self::SinkReconcile { binding, body, deadline_ms } => {
                binding.validate()?;
                validate_body(body)?;
                if *deadline_ms == 0 {
                    return Err(WireValidationError::InvalidField("deadline_ms"));
                }
            }
            Self::SinkReadback { binding, deadline_ms } => {
                binding.validate()?;
                if *deadline_ms == 0 {
                    return Err(WireValidationError::InvalidField("deadline_ms"));
                }
            }
            Self::SourceReadback { request } => request.validate()?,
        }
        Ok(())
    }
}

/// Kernel-side source-readback request projection, intentionally omitting the
/// Store `StateFence`. Kernel derives that fence from the retained grant and its
/// current authority snapshot when building the Store-facing request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessStreamKernelSourceReadbackRequest {
    pub wire_revision: u16,
    pub job_id: String,
    pub invocation_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub process_binding_json: String,
    pub process_binding_sha256: String,
    pub stream: ProcessStreamKind,
    pub locator_kind: DurableStreamLocatorKind,
    pub locator: String,
    pub ready_receipt_ref: String,
    pub expected_sha256: String,
    pub expected_byte_length: u64,
    pub policy: ProcessStreamPolicyBinding,
    pub policy_json: String,
    pub policy_sha256: String,
    pub max_bytes: u64,
    pub offset: u64,
    pub chunk_limit: u32,
    pub deadline_ms: u64,
}

impl BlobProcessStreamKernelSourceReadbackRequest {
    /// Validates all semantic fields that do not depend on Kernel's current
    /// `StateFence`. The owning Kernel adapter validates again after inserting
    /// the current fence into `ProcessStreamSourceReadbackRequest`.
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
        if self.max_bytes < self.expected_byte_length
            || self.offset > self.expected_byte_length
            || self.chunk_limit != PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES
            || self.deadline_ms == 0
        {
            return Err(WireValidationError::InvalidField("chunk"));
        }
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

    /// Constructs the Store-facing request under Kernel's current fence.
    pub fn with_state_fence(
        &self,
        fence: StateFence,
        capability: ProcessStreamSinkCapabilityRef,
        binding: ProcessStreamSinkBindingRef,
    ) -> Result<ProcessStreamSourceReadbackRequest, WireValidationError> {
        self.validate()?;
        capability.validate()?;
        binding.validate()?;
        let request = ProcessStreamSourceReadbackRequest {
            wire_revision: self.wire_revision,
            capability,
            binding,
            job_id: self.job_id.clone(),
            invocation_id: self.invocation_id.clone(),
            operation_id: self.operation_id.clone(),
            process_tree_id: self.process_tree_id.clone(),
            process_binding_json: self.process_binding_json.clone(),
            process_binding_sha256: self.process_binding_sha256.clone(),
            stream: self.stream,
            locator_kind: self.locator_kind,
            locator: self.locator.clone(),
            ready_receipt_ref: self.ready_receipt_ref.clone(),
            expected_sha256: self.expected_sha256.clone(),
            expected_byte_length: self.expected_byte_length,
            policy: self.policy.clone(),
            policy_json: self.policy_json.clone(),
            policy_sha256: self.policy_sha256.clone(),
            fence,
            max_bytes: self.max_bytes,
            offset: self.offset,
            chunk_limit: self.chunk_limit,
            deadline_ms: self.deadline_ms,
        };
        request.validate()?;
        Ok(request)
    }
}

fn validate_body(body: &serde_json::Value) -> Result<(), WireValidationError> {
    let encoded = serde_json::to_vec(body).map_err(|_| WireValidationError::InvalidField("body"))?;
    if !body.is_object() || encoded.len() > PROCESS_STREAM_SINK_MAX_BODY_BYTES {
        return Err(WireValidationError::InvalidField("body"));
    }
    Ok(())
}

/// Exact Kernel request for a fresh owner-side WorkScope/source/policy facts
/// read. The request uses only already admitted job/process identities and
/// carries no candidate owner facts from `TestD`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessStreamOwnerFactsPullRequest {
    /// Closed operation selector.
    pub wire_id: String,
    /// Closed operation revision.
    pub wire_revision: u16,
    /// Kernel-generated durable pull reference.
    pub pull_ref: String,
    /// Exact durable `TestD` job identity.
    pub job_id: String,
    /// Exact admitted invocation identity.
    pub invocation_id: String,
    /// Exact admitted ProcessExecutionBinding JSON.
    pub process_binding_json: String,
    /// SHA-256 of the exact process binding bytes.
    pub process_binding_sha256: String,
    /// Digest of the authenticated outer Kernel request identity.
    pub outer_request_sha256: String,
    /// WorkScope ID from the authenticated request metadata.
    pub work_scope_ref: String,
    /// Task ID from authenticated metadata, if selected.
    pub task_ref: Option<String>,
    /// Task revision from the authenticated StateFence, if selected.
    pub task_revision: Option<u64>,
    /// Digest of the exact canonical source-root identity after Kernel checks it.
    pub source_root_identity_sha256: String,
    /// Authenticated outer request fence.
    pub state_fence: StateFence,
    /// Absolute Unix-millisecond deadline.
    pub deadline_ms: u64,
}

impl BlobProcessStreamOwnerFactsPullRequest {
    /// Validates the exact pull identity and bounded request.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        if self.wire_id != BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_ID
            || self.wire_revision != BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_REVISION
        {
            return Err(WireValidationError::UnsupportedRevision);
        }
        for (field, value) in [
            ("pull_ref", self.pull_ref.as_str()),
            ("job_id", self.job_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
            ("work_scope_ref", self.work_scope_ref.as_str()),
        ] {
            validate_text(field, value)?;
        }
        if let Some(task_ref) = &self.task_ref {
            validate_text("task_ref", task_ref)?;
        }
        if self.task_ref.is_some() != self.task_revision.is_some()
            || self.task_revision.is_some_and(|revision| revision == 0)
        {
            return Err(WireValidationError::InvalidField("task_binding"));
        }
        validate_digest("process_binding_sha256", &self.process_binding_sha256)?;
        validate_digest("outer_request_sha256", &self.outer_request_sha256)?;
        validate_digest("source_root_identity_sha256", &self.source_root_identity_sha256)?;
        if self.process_binding_json.len() > 16 * 1024
            || !json_object(&self.process_binding_json)
            || sha256_hex(self.process_binding_json.as_bytes()) != self.process_binding_sha256
            || self.deadline_ms == 0
        {
            return Err(WireValidationError::InvalidField("process_binding"));
        }
        self.state_fence
            .validate()
            .map_err(|_| WireValidationError::InvalidField("state_fence"))?;
        let encoded = serde_json::to_vec(self)
            .map_err(|_| WireValidationError::InvalidField("frame"))?;
        if encoded.len() > BLOB_PROCESS_STREAM_KERNEL_MAX_FRAME_BYTES {
            return Err(WireValidationError::InvalidField("frame"));
        }
        Ok(())
    }
}

/// Closed result of the exact authenticated owner-facts pull.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessStreamOwnerFactsPullResponse {
    /// Closed operation selector.
    pub wire_id: String,
    /// Closed operation revision.
    pub wire_revision: u16,
    /// Exact pull reference answered by the daemon owner.
    pub pull_ref: String,
    /// Exact job identity answered.
    pub job_id: String,
    /// Exact invocation identity answered.
    pub invocation_id: String,
    /// Exact process binding digest answered.
    pub process_binding_sha256: String,
    /// Exact outer request digest answered.
    pub outer_request_sha256: String,
    /// Exact state fence observed by the daemon owner.
    pub observed_state_fence: StateFence,
    /// Owner result. Available carries opaque receipt references and their
    /// digests only; Kernel and Store resolve those through the trusted owner.
    pub outcome: BlobProcessStreamOwnerFactsPullOutcome,
}

/// Closed owner-facts pull disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum BlobProcessStreamOwnerFactsPullOutcome {
    /// All independent verified owner facts needed by the Store resolver are
    /// current and refer to the exact WorkScope/source/process binding.
    Available {
        /// Opaque resolver lookup reference for the complete validated fact set.
        owner_facts_ref: String,
        /// Digest of the complete owner-facts record.
        owner_facts_sha256: String,
        /// WorkScope snapshot digest.
        work_scope_snapshot_sha256: String,
        /// Matched WorkScope guard receipt reference/digest.
        matched_guard_receipt_ref: String,
        matched_guard_receipt_sha256: String,
        /// Independent canonical source receipt reference/digest.
        canonical_source_receipt_ref: String,
        canonical_source_receipt_sha256: String,
        /// Current policy selection reference/digest.
        policy_ref: String,
        policy_sha256: String,
        /// Full six-domain residency selection reference/digest.
        residency_ref: String,
        residency_sha256: String,
        /// Actual causal parent/genesis receipt reference/digest.
        causal_receipt_ref: String,
        causal_receipt_sha256: String,
        /// Current authority binding reference/digest.
        authority_ref: String,
        authority_sha256: String,
        /// Owner-compiled currentness digest over all facts above.
        currentness_sha256: String,
    },
    /// The owner lacks one or more independent facts or the exact binding is stale.
    Unavailable {
        /// Closed non-sensitive refusal reason.
        reason: BlobProcessStreamOwnerFactsUnavailableReason,
    },
}

/// Owner-facts refusal reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlobProcessStreamOwnerFactsUnavailableReason {
    ScopeGuardUnavailable,
    SourceReceiptUnavailable,
    PolicyUnavailable,
    ResidencyUnavailable,
    CausalEvidenceUnavailable,
    AuthorityUnavailable,
    StaleBinding,
    DeadlineElapsed,
}

impl BlobProcessStreamOwnerFactsPullResponse {
    /// Validates bounded values and owner-result proof commitments.
    pub fn validate(&self) -> Result<(), WireValidationError> {
        if self.wire_id != BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_ID
            || self.wire_revision != BLOB_PROCESS_STREAM_OWNER_FACTS_WIRE_REVISION
        {
            return Err(WireValidationError::UnsupportedRevision);
        }
        for (field, value) in [
            ("pull_ref", self.pull_ref.as_str()),
            ("job_id", self.job_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
        ] {
            validate_text(field, value)?;
        }
        validate_digest("process_binding_sha256", &self.process_binding_sha256)?;
        validate_digest("outer_request_sha256", &self.outer_request_sha256)?;
        self.observed_state_fence
            .validate()
            .map_err(|_| WireValidationError::InvalidField("observed_state_fence"))?;
        if let BlobProcessStreamOwnerFactsPullOutcome::Available {
            owner_facts_ref,
            owner_facts_sha256,
            work_scope_snapshot_sha256,
            matched_guard_receipt_ref,
            matched_guard_receipt_sha256,
            canonical_source_receipt_ref,
            canonical_source_receipt_sha256,
            policy_ref,
            policy_sha256,
            residency_ref,
            residency_sha256,
            causal_receipt_ref,
            causal_receipt_sha256,
            authority_ref,
            authority_sha256,
            currentness_sha256,
        } = &self.outcome
        {
            for (field, value) in [
                ("owner_facts_ref", owner_facts_ref),
                ("matched_guard_receipt_ref", matched_guard_receipt_ref),
                ("canonical_source_receipt_ref", canonical_source_receipt_ref),
                ("policy_ref", policy_ref),
                ("residency_ref", residency_ref),
                ("causal_receipt_ref", causal_receipt_ref),
                ("authority_ref", authority_ref),
            ] {
                validate_text(field, value)?;
            }
            for (field, value) in [
                ("owner_facts_sha256", owner_facts_sha256),
                ("work_scope_snapshot_sha256", work_scope_snapshot_sha256),
                ("matched_guard_receipt_sha256", matched_guard_receipt_sha256),
                ("canonical_source_receipt_sha256", canonical_source_receipt_sha256),
                ("policy_sha256", policy_sha256),
                ("residency_sha256", residency_sha256),
                ("causal_receipt_sha256", causal_receipt_sha256),
                ("authority_sha256", authority_sha256),
                ("currentness_sha256", currentness_sha256),
            ] {
                validate_digest(field, value)?;
            }
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|_| WireValidationError::InvalidField("frame"))?;
        if encoded.len() > BLOB_PROCESS_STREAM_KERNEL_MAX_FRAME_BYTES {
            return Err(WireValidationError::InvalidField("frame"));
        }
        Ok(())
    }

    /// Checks that an owner result answers the exact pull request.
    pub fn validate_for_request(
        &self,
        request: &BlobProcessStreamOwnerFactsPullRequest,
    ) -> Result<(), WireValidationError> {
        request.validate()?;
        self.validate()?;
        if self.pull_ref != request.pull_ref
            || self.job_id != request.job_id
            || self.invocation_id != request.invocation_id
            || self.process_binding_sha256 != request.process_binding_sha256
            || self.outer_request_sha256 != request.outer_request_sha256
            || self.observed_state_fence != request.state_fence
        {
            return Err(WireValidationError::InvalidField("owner_facts_binding"));
        }
        Ok(())
    }
}

impl BlobProcessStreamKernelRequest {
    /// Constructs a narrow Kernel exchange with a digest over the exact
    /// typed operation envelope.
    pub fn new(
        capability: ProcessStreamSinkCapabilityRef,
        call_token: BlobProcessStreamCallToken,
        operation: BlobProcessStreamKernelOperationRequest,
    ) -> Result<Self, WireValidationError> {
        operation.validate()?;
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

/// Result of one narrow authenticated `TestD`-to-Kernel capability operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum BlobProcessStreamKernelOutcome {
    /// Exact typed owner response retained for this token and operation digest.
    Completed {
        /// Digest of the original operation body.
        operation_sha256: String,
        /// Exact closed Store/Blob result.
        response: Box<BlobProcessStreamFrameResponse>,
        /// Original terminal request, retained verbatim when this outcome
        /// finalizes or aborts a stream. This lets a recovering `TestD` process
        /// reconstruct the owner-validated terminal against the exact
        /// command, rather than treating metadata readback as a terminal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_terminal_request: Option<Box<BlobProcessStreamKernelOperationRequest>>,
        /// Digest of the retained original terminal request above.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_terminal_operation_sha256: Option<String>,
    },
    /// Kernel proved that the original token was reserved and no Store call began.
    NotStarted {
        /// Original operation digest.
        operation_sha256: String,
    },
    /// Kernel refused before consulting Store because the exact retained
    /// capability, verified owner facts, current fence, or negotiated Blob
    /// service was unavailable. This is not a proof that an earlier call did
    /// not start and must not authorize a blind retry.
    Unavailable {
        /// Original operation digest.
        operation_sha256: String,
        /// Closed non-sensitive reason code.
        reason: BlobProcessStreamUnavailableReason,
    },
    /// Kernel cannot prove whether the original Store call completed.
    Unknown {
        /// Original operation digest.
        operation_sha256: String,
    },
}

/// Closed reason for a pre-effect Kernel capability refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlobProcessStreamUnavailableReason {
    /// No exact durable capability grant exists for the reference.
    GrantUnavailable,
    /// The grant lacks one or more verified owner facts needed by Store.
    OwnerFactsUnavailable,
    /// The retained grant is not current for this session/fence/generation.
    StaleCapability,
    /// The separately negotiated Blob process-stream service is not ready.
    ServiceUnavailable,
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
                original_terminal_request,
                original_terminal_operation_sha256,
            } => {
                validate_digest("operation_sha256", operation_sha256)?;
                response.validate()?;
                match (original_terminal_request, original_terminal_operation_sha256) {
                    (Some(request), Some(original_sha256)) => {
                        request.validate()?;
                        validate_digest("original_terminal_operation_sha256", original_sha256)?;
                        if !matches!(
                            request,
                            BlobProcessStreamKernelOperationRequest::SinkFinalize { .. }
                                | BlobProcessStreamKernelOperationRequest::SinkAbort { .. }
                        ) || sha256_hex(
                            &serde_json::to_vec(request)
                                .map_err(|_| WireValidationError::InvalidField(
                                    "original_terminal_request",
                                ))?,
                        ) != *original_sha256
                        {
                            return Err(WireValidationError::InvalidField(
                                "original_terminal_request",
                            ));
                        }
                    }
                    (None, None) => {}
                    _ => {
                        return Err(WireValidationError::InvalidField(
                            "original_terminal_request",
                        ));
                    }
                }
            }
            BlobProcessStreamKernelOutcome::NotStarted { operation_sha256 }
            | BlobProcessStreamKernelOutcome::Unavailable {
                operation_sha256,
                ..
            }
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
            | BlobProcessStreamKernelOutcome::Unavailable {
                operation_sha256,
                ..
            }
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
    /// Kernel-issued capability reference associated with the admitted job.
    pub capability: ProcessStreamSinkCapabilityRef,
    /// Store-issued reference for the exact original Open session.
    pub binding: ProcessStreamSinkBindingRef,
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
        self.capability.validate()?;
        self.binding.validate()?;
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
    /// Opaque Store-generated lookup reference bound to this authenticated
    /// connection, Kernel capability, and exact Open request.
    pub binding_ref: String,
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
        validate_text("binding_ref", &self.binding_ref)?;
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
        body: Box<serde_json::Value>,
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
        body: Box<serde_json::Value>,
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
        body: Box<serde_json::Value>,
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
        body: Box<serde_json::Value>,
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
        body: Box<serde_json::Value>,
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
        body: Box<serde_json::Value>,
    },
    /// Finalize returned owner-validated terminal evidence JSON.
    Finalized {
        /// Closed terminal projection JSON.
        body: Box<serde_json::Value>,
    },
    /// Abort returned owner-validated terminal evidence JSON.
    Aborted {
        /// Closed terminal projection JSON.
        body: Box<serde_json::Value>,
    },
    /// Readback returned the exact retained owner observation JSON.
    Readback {
        /// Closed ProcessStreamSinkReadback JSON.
        body: Box<serde_json::Value>,
    },
    /// Owner proved the exact original command never started.
    NotStarted,
    /// The exact original command outcome remains unknown.
    Unknown,
    /// The owner rejected the request before an effect could begin.
    Unavailable {
        /// Closed pre-effect refusal category.
        reason: ProcessStreamSinkUnavailableReason,
    },
}

/// Closed process-stream sink refusal category. It carries no provider prose.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStreamSinkUnavailableReason {
    ProviderUnavailable,
    AdmissionFenced,
    RequestRejected,
    Capacity,
}

/// Closed outcome of a source readback/reconciliation request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProcessStreamSourceReadbackResponse {
    /// Exact ready source bytes plus owner-issued receipt evidence.
    Ready {
        /// Bounded ephemeral source bytes; clients must not persist this field.
        bytes: Vec<u8>,
        /// Original whole-source SHA-256 commitment, distinct from this
        /// response chunk's observed SHA-256.
        whole_source_sha256: String,
        /// Original whole-source byte length, distinct from this chunk's size.
        whole_source_byte_length: u64,
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
