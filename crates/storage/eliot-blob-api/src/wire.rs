//! Closed EBP payloads for authenticated process-stream source readback.
//!
//! These semantic records intentionally carry no Blob lease, receipt context,
//! stage context, filesystem path, or caller-issued receipt. The Store binds
//! each request to the owner-retained stream session before consulting Blob.

use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};

/// Wire revision for the authenticated Store-to-Blob readback exchange.
pub const PROCESS_STREAM_READBACK_WIRE_REVISION: u16 = 1;
/// Maximum raw bytes carried by one JSON EBP source-readback response.
///
/// JSON encodes each byte as a decimal integer, so the frame cost can exceed
/// the source size. This bound stays well below EBP's 4 MiB frame ceiling.
pub const PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES: u32 = 256 * 1024;

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
