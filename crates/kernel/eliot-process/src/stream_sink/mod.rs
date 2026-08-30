//! Bounded provider-neutral process stream persistence-session contract.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde::Serialize;
use thiserror::Error;

use super::{
    ProcessExecutionBinding, ProcessStreamEvidence, ProcessStreamEvidenceError, ProcessStreamKind,
    ProcessStreamPolicyBinding, ProcessStreamPrefixPreview, ProcessStreamTransformationBinding,
    StreamEvidenceGap, StreamPersistenceStatus, StreamTransportStatus,
};

pub const PROCESS_STREAM_SINK_SCHEMA_VERSION: &str = "eliot-process-stream-sink-v1";
const MAX_REFERENCE_BYTES: usize = 256;
const MAX_PREVIEW_BYTES: u64 = 16 * 1024 * 1024;

mod port;
mod requests;
mod terminal;
mod types;

pub use port::{ProcessStreamSinkClient, ProcessStreamSinkFuture};
pub use requests::{
    ProcessStreamSinkAbortReason, ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend,
    ProcessStreamSinkAppendDisposition, ProcessStreamSinkFinalizeRequest,
    ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback, ProcessStreamSinkSessionView,
    ProcessStreamSinkUnknownOutcome,
};
pub use terminal::{ProcessStreamSinkSession, ProcessStreamSinkTerminal};
pub use types::{
    ProcessStreamDigestAlgorithm, ProcessStreamSinkLimits, ProcessStreamSinkSessionId,
    ProcessStreamSinkSourceId, ProcessStreamSinkState, ProcessStreamSinkTerminalId,
};

#[cfg(test)]
mod tests;

fn validate_reference(field: &'static str, value: &str) -> Result<(), ProcessStreamSinkError> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > MAX_REFERENCE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ProcessStreamSinkError::InvalidReference { field });
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), ProcessStreamSinkError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProcessStreamSinkError::InvalidDigest { field });
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(
    field: &'static str,
    value: &T,
) -> Result<String, ProcessStreamSinkError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| ProcessStreamSinkError::Serialization {
            field,
            reason: error.to_string(),
        })
}

fn validate_binding(binding: &ProcessExecutionBinding) -> Result<(), ProcessStreamSinkError> {
    let wire = serde_json::to_value(binding).map_err(|_| ProcessStreamSinkError::InvalidBinding)?;
    let object = wire
        .as_object()
        .ok_or(ProcessStreamSinkError::InvalidBinding)?;
    for field in [
        "operation_id",
        "process_tree_id",
        "job_id",
        "image_id",
        "session_id",
        "action_lease_ref",
        "authority_id",
    ] {
        let value = object
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or(ProcessStreamSinkError::InvalidBinding)?;
        if value.is_empty()
            || value.len() > MAX_REFERENCE_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ProcessStreamSinkError::InvalidBinding);
        }
    }
    let epoch = object
        .get("authority_epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ProcessStreamSinkError::InvalidBinding)?;
    let revision = object
        .get("validation_revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ProcessStreamSinkError::InvalidBinding)?;
    let generation = object
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ProcessStreamSinkError::InvalidBinding)?;
    let fence = object
        .get("state_fence")
        .and_then(serde_json::Value::as_object)
        .ok_or(ProcessStreamSinkError::InvalidBinding)?;
    if epoch == 0
        || revision == 0
        || generation == 0
        || fence
            .get("authority_epoch")
            .and_then(serde_json::Value::as_u64)
            != Some(epoch)
        || fence.get("generation").and_then(serde_json::Value::as_u64) != Some(generation)
        || fence
            .get("nonce")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|value| {
                value.is_empty()
                    || value.len() > MAX_REFERENCE_BYTES
                    || value.chars().any(char::is_control)
            })
    {
        return Err(ProcessStreamSinkError::InvalidBinding);
    }
    for field in ["request_digest", "permit_digest", "effect_digest"] {
        let value = object
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or(ProcessStreamSinkError::InvalidBinding)?;
        validate_digest("process_execution_binding.digest", value)
            .map_err(|_| ProcessStreamSinkError::InvalidBinding)?;
    }
    Ok(())
}

fn validate_evidence(evidence: &ProcessStreamEvidence) -> Result<(), ProcessStreamSinkError> {
    evidence
        .validate()
        .map_err(|error| ProcessStreamSinkError::EvidenceInvariant {
            reason: error.to_string(),
        })
}

fn map_evidence_error(error: &ProcessStreamEvidenceError) -> ProcessStreamSinkError {
    ProcessStreamSinkError::EvidenceInvariant {
        reason: error.to_string(),
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProcessStreamSinkError {
    #[error("invalid reference {field}")]
    InvalidReference { field: &'static str },
    #[error("invalid SHA-256 digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid sink limits: {reason}")]
    InvalidLimits { reason: &'static str },
    #[error("invalid process execution binding")]
    InvalidBinding,
    #[error("invalid sink request: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("session identity mismatch")]
    SessionMismatch,
    #[error("process binding mismatch")]
    BindingMismatch,
    #[error("stream identity mismatch")]
    StreamMismatch,
    #[error("policy binding mismatch")]
    PolicyMismatch,
    #[error("source identity mismatch")]
    SourceMismatch,
    #[error("open request digest mismatch")]
    OpenDigestMismatch,
    #[error("sequence gap: expected {expected}, observed {observed}")]
    SequenceGap { expected: u64, observed: u64 },
    #[error("offset mismatch: expected {expected}, observed {observed}")]
    OffsetMismatch { expected: u64, observed: u64 },
    #[error("overlapping or out-of-order append")]
    OverlapOrOutOfOrder,
    #[error("mismatched append replay")]
    MismatchedReplay,
    #[error("chunk size exceeds the session ceiling")]
    ChunkLimitExceeded,
    #[error("total admitted bytes exceed the session ceiling")]
    TotalLimitExceeded,
    #[error("admitted chunk count exceeds the session ceiling")]
    ChunkCountLimitExceeded,
    #[error("preview exceeds the session ceiling")]
    PreviewLimitExceeded,
    #[error("in-flight chunk ceiling exceeded")]
    InFlightChunkLimitExceeded,
    #[error("in-flight byte ceiling exceeded")]
    InFlightByteLimitExceeded,
    #[error("append is not permitted after finalizing")]
    AppendAfterFinalizing,
    #[error("session is terminal")]
    Terminal,
    #[error("terminal identity conflicts with the existing terminal")]
    TerminalIdentityConflict,
    #[error("terminal/evidence invariant failed: {reason}")]
    EvidenceInvariant { reason: String },
    #[error("provider unavailable before an exact session result")]
    ProviderUnavailable,
    #[error("serialization failed for {field}: {reason}")]
    Serialization { field: &'static str, reason: String },
}

impl From<ProcessStreamEvidenceError> for ProcessStreamSinkError {
    fn from(error: ProcessStreamEvidenceError) -> Self {
        map_evidence_error(&error)
    }
}

fn validate_gaps(gaps: &[StreamEvidenceGap]) -> Result<(), ProcessStreamSinkError> {
    if gaps.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ProcessStreamSinkError::InvalidRequest {
            reason: "gaps must be unique and canonically sorted",
        });
    }
    Ok(())
}

fn validate_preview_limit(
    preview: &ProcessStreamPrefixPreview,
    limits: &ProcessStreamSinkLimits,
) -> Result<(), ProcessStreamSinkError> {
    if preview.retained_bytes() > limits.max_preview_bytes() {
        return Err(ProcessStreamSinkError::PreviewLimitExceeded);
    }
    Ok(())
}

fn validate_terminal_evidence(
    state: types::ProcessStreamSinkState,
    evidence: &ProcessStreamEvidence,
) -> Result<(), ProcessStreamSinkError> {
    validate_evidence(evidence)?;
    let gaps = evidence.gaps();
    match state {
        types::ProcessStreamSinkState::CompleteSource => {
            if evidence.transport() != StreamTransportStatus::Complete
                || evidence.persistence() != StreamPersistenceStatus::CompleteSource
                || evidence.source().is_none()
                || !gaps.is_empty()
            {
                return Err(ProcessStreamSinkError::EvidenceInvariant {
                    reason: "complete source state requires complete transport, persistence, source and no gaps".to_owned(),
                });
            }
        }
        types::ProcessStreamSinkState::PartialSource => {
            if evidence.persistence() != StreamPersistenceStatus::PartialSource
                || evidence.source().is_none()
                || gaps.is_empty()
            {
                return Err(ProcessStreamSinkError::EvidenceInvariant {
                    reason: "partial source state requires a source and explicit coverage gap"
                        .to_owned(),
                });
            }
        }
        types::ProcessStreamSinkState::SourceUnavailable => {
            if evidence.persistence() != StreamPersistenceStatus::SourceUnavailable
                || evidence.source().is_some()
                || gaps.is_empty()
            {
                return Err(ProcessStreamSinkError::EvidenceInvariant {
                    reason: "source unavailable state requires no source and an availability gap"
                        .to_owned(),
                });
            }
        }
        types::ProcessStreamSinkState::PolicyProhibited
        | types::ProcessStreamSinkState::RedactionFailed => {
            if evidence.persistence() != StreamPersistenceStatus::SourceUnavailable
                || evidence.source().is_some()
                || evidence.preview().bytes_len_for_sink() != 0
                || (state == types::ProcessStreamSinkState::PolicyProhibited
                    && !gaps.contains(&StreamEvidenceGap::PolicyProhibited))
                || (state == types::ProcessStreamSinkState::RedactionFailed
                    && !gaps.contains(&StreamEvidenceGap::RedactionFailed))
            {
                return Err(ProcessStreamSinkError::EvidenceInvariant {
                    reason: "policy or redaction terminal cannot retain source bytes".to_owned(),
                });
            }
        }
        types::ProcessStreamSinkState::PersistenceFailed => {
            if evidence.persistence() == StreamPersistenceStatus::CompleteSource
                || !gaps.contains(&StreamEvidenceGap::PersistenceFailed)
            {
                return Err(ProcessStreamSinkError::EvidenceInvariant {
                    reason: "persistence failure cannot claim complete source".to_owned(),
                });
            }
        }
        types::ProcessStreamSinkState::Cancelled
        | types::ProcessStreamSinkState::UnknownOutcome => {
            let required_gap = if state == types::ProcessStreamSinkState::Cancelled {
                StreamEvidenceGap::CancelledBeforeEof
            } else {
                StreamEvidenceGap::UnknownOutcome
            };
            if evidence.persistence() == StreamPersistenceStatus::CompleteSource
                || !gaps.contains(&required_gap)
            {
                return Err(ProcessStreamSinkError::EvidenceInvariant {
                    reason: "cancelled or unknown terminal cannot claim complete source".to_owned(),
                });
            }
        }
        types::ProcessStreamSinkState::Opening
        | types::ProcessStreamSinkState::Open
        | types::ProcessStreamSinkState::Finalizing => {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "non-terminal state cannot construct a terminal".to_owned(),
            });
        }
    }
    Ok(())
}

trait SinkPreviewExt {
    fn bytes_len_for_sink(&self) -> u64;
}

impl SinkPreviewExt for ProcessStreamPrefixPreview {
    fn bytes_len_for_sink(&self) -> u64 {
        u64::try_from(self.bytes().len()).unwrap_or(u64::MAX)
    }
}
