/// Typed contract failure; no raw stream or secret content is included.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProcessStreamEvidenceError {
    /// A reference is missing, non-canonical, contains controls or exceeds its bound.
    #[error("invalid reference {field}")]
    InvalidReference { field: &'static str },
    /// A digest is not canonical lowercase SHA-256.
    #[error("invalid SHA-256 digest in {field}")]
    InvalidDigest { field: &'static str },
    /// A bounded collection or preview exceeds its contract ceiling.
    #[error("{field} exceeds limit {limit}")]
    LimitExceeded { field: &'static str, limit: usize },
    /// A cross-field invariant was violated.
    #[error("invalid {field}: {reason}")]
    Invariant {
        field: &'static str,
        reason: &'static str,
    },
    /// The exact process binding is malformed or internally inconsistent.
    #[error("process execution binding is invalid")]
    InvalidBinding,
    /// Raw capture tried to claim parsing/evaluation authority.
    #[error("raw process-stream evidence cannot claim parser or evaluator authority")]
    AuthorityEscalation,
    /// Canonical identity serialization failed.
    #[error("cannot serialize process-stream evidence identity: {0}")]
    Serialization(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessExecutionBindingValidationWire {
    operation_id: OperationId,
    process_tree_id: ProcessTreeId,
    job_id: JobId,
    image_id: ImageId,
    session_id: SessionId,
    generation: Generation,
    action_lease_ref: ActionLeaseRef,
    authority_id: DispatchAuthorityId,
    authority_epoch: u64,
    state_fence: FencingToken,
    request_digest: String,
    permit_digest: String,
    effect_digest: String,
    validation_revision: u64,
}

fn validate_process_execution_binding(
    binding: &ProcessExecutionBinding,
) -> Result<(), ProcessStreamEvidenceError> {
    let serialized = serde_json::to_value(binding)
        .map_err(|_| ProcessStreamEvidenceError::InvalidBinding)?;
    let wire: ProcessExecutionBindingValidationWire = serde_json::from_value(serialized)
        .map_err(|_| ProcessStreamEvidenceError::InvalidBinding)?;

    for value in [
        wire.operation_id.as_str(),
        wire.process_tree_id.as_str(),
        wire.job_id.as_str(),
        wire.image_id.as_str(),
        wire.session_id.as_str(),
        wire.action_lease_ref.as_str(),
        wire.authority_id.as_str(),
        wire.state_fence.nonce(),
    ] {
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(ProcessStreamEvidenceError::InvalidBinding);
        }
    }
    if wire.generation.get() == 0
        || wire.authority_epoch == 0
        || wire.validation_revision == 0
        || wire.state_fence.authority_epoch() != wire.authority_epoch
        || wire.state_fence.generation() != wire.generation
    {
        return Err(ProcessStreamEvidenceError::InvalidBinding);
    }
    for digest in [
        wire.request_digest.as_str(),
        wire.permit_digest.as_str(),
        wire.effect_digest.as_str(),
    ] {
        if validate_digest("process_execution_binding.digest", digest).is_err() {
            return Err(ProcessStreamEvidenceError::InvalidBinding);
        }
    }
    Ok(())
}

const TRANSPORT_GAPS: [StreamEvidenceGap; 4] = [
    StreamEvidenceGap::TransportReadFailed,
    StreamEvidenceGap::CancelledBeforeEof,
    StreamEvidenceGap::CaptureUnavailable,
    StreamEvidenceGap::UnknownOutcome,
];

const SOURCE_UNAVAILABLE_GAPS: [StreamEvidenceGap; 7] = [
    StreamEvidenceGap::PolicyProhibited,
    StreamEvidenceGap::PersistenceUnavailable,
    StreamEvidenceGap::PersistenceBackpressure,
    StreamEvidenceGap::PersistenceFailed,
    StreamEvidenceGap::PersistenceUnknownOutcome,
    StreamEvidenceGap::RedactionFailed,
    StreamEvidenceGap::CaptureUnavailable,
];

const fn expected_transport_gap(status: StreamTransportStatus) -> Option<StreamEvidenceGap> {
    match status {
        StreamTransportStatus::Complete => None,
        StreamTransportStatus::ReadFailed => Some(StreamEvidenceGap::TransportReadFailed),
        StreamTransportStatus::CancelledBeforeEof => Some(StreamEvidenceGap::CancelledBeforeEof),
        StreamTransportStatus::CaptureUnavailable => Some(StreamEvidenceGap::CaptureUnavailable),
        StreamTransportStatus::UnknownOutcome => Some(StreamEvidenceGap::UnknownOutcome),
    }
}

fn omitted_suffix(
    retained_bytes: u64,
    represented_bytes: u64,
) -> Result<Vec<StreamByteRange>, ProcessStreamEvidenceError> {
    if retained_bytes == represented_bytes {
        Ok(Vec::new())
    } else {
        Ok(vec![StreamByteRange::new(
            retained_bytes,
            represented_bytes,
        )?])
    }
}

fn usize_to_u64(
    field: &'static str,
    value: usize,
) -> Result<u64, ProcessStreamEvidenceError> {
    u64::try_from(value).map_err(|_| ProcessStreamEvidenceError::Invariant {
        field,
        reason: "length does not fit u64",
    })
}

fn validate_reference(
    field: &'static str,
    value: &str,
) -> Result<(), ProcessStreamEvidenceError> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > MAX_REFERENCE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ProcessStreamEvidenceError::InvalidReference { field });
    }
    Ok(())
}

fn validate_locator(value: &str) -> Result<(), ProcessStreamEvidenceError> {
    validate_reference("source.locator", value)?;
    let (scheme, _) = value
        .split_once(':')
        .ok_or(ProcessStreamEvidenceError::InvalidReference {
            field: "source.locator",
        })?;
    let scheme = scheme.to_ascii_lowercase();
    if matches!(
        scheme.as_str(),
        "raw" | "memory" | "process-memory" | "process_memory"
    ) {
        return Err(ProcessStreamEvidenceError::Invariant {
            field: "source.locator",
            reason: "synthetic or process-memory locators are forbidden",
        });
    }
    Ok(())
}

fn validate_digest(
    field: &'static str,
    value: &str,
) -> Result<(), ProcessStreamEvidenceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ProcessStreamEvidenceError::InvalidDigest { field });
    }
    Ok(())
}
