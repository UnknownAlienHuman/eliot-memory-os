use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("service {service} is not ready: {reason}")]
    ServiceNotReady { service: String, reason: String },

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
