use std::path::PathBuf;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingleInstanceRefusal {
    LiveOwner,
    ContradictoryIdentity,
    MalformedIdentity,
    InaccessibleEvidence,
    UnknownOwner,
    AmbiguousLineage,
    ReplacementDetected,
    UnsupportedPlatform,
}

impl std::fmt::Display for SingleInstanceRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::LiveOwner => "live-owner",
            Self::ContradictoryIdentity => "contradictory-identity",
            Self::MalformedIdentity => "malformed-identity",
            Self::InaccessibleEvidence => "inaccessible-evidence",
            Self::UnknownOwner => "unknown-owner",
            Self::AmbiguousLineage => "ambiguous-lineage",
            Self::ReplacementDetected => "replacement-detected",
            Self::UnsupportedPlatform => "unsupported-platform",
        };
        write!(formatter, "{code}")
    }
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("service {service} is not ready: {reason}")]
    ServiceNotReady { service: String, reason: String },

    #[error("single-instance lock contention at {lock_path}: {refusal} ({detail})")]
    SingleInstanceContention {
        lock_path: PathBuf,
        refusal: SingleInstanceRefusal,
        detail: String,
    },

    #[error("single-instance acquisition failed at {stage}: {detail}")]
    SingleInstanceAcquisitionFailed { stage: String, detail: String },

    #[error("write rejected: {0}")]
    WriteRejected(String),

    #[error("encoding rejected")]
    EncodingRejected {
        violations: Vec<eliot_types::TextEncodingViolation>,
    },

    #[error("observability write_id conflicts with a different payload")]
    ObservabilityConflict,

    #[error("writer backpressure")]
    Backpressure,

    #[error("writer response channel closed")]
    WriterClosed,

    #[error("runtime supervision failed: {0}")]
    RuntimeSupervision(String),

    #[error("canonical commit outcome is still unknown for write_id {write_id}")]
    UnknownCommit { write_id: eliot_types::WriteId },

    #[error("canonical store is unavailable; write_id {write_id} remains retryable: {reason}")]
    RetryableWriteUnavailable {
        write_id: eliot_types::WriteId,
        reason: String,
    },

    #[error(
        "project {project_id} is paused while write_id {unknown_write_id} has an unknown commit outcome"
    )]
    ProjectWritePaused {
        project_id: eliot_types::ProjectId,
        unknown_write_id: eliot_types::WriteId,
    },

    #[error("stale read: project revision {actual} is below required {required}")]
    StaleRead { required: u64, actual: u64 },

    #[error(
        "context packet floor exceeds budget: estimated {estimated_tokens} tokens > max {max_tokens}"
    )]
    PacketFloorExceedsBudget {
        max_tokens: usize,
        estimated_tokens: usize,
        section_tokens: std::collections::BTreeMap<String, usize>,
    },

    #[error(transparent)]
    Store(#[from] eliot_store::StoreError),

    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
