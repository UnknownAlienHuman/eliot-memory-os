use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

use super::{MAX_PREVIEW_BYTES, ProcessStreamSinkError, validate_reference};

macro_rules! checked_id {
    ($name:ident, $field:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ProcessStreamSinkError> {
                let value = value.into();
                validate_reference($field, &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

checked_id!(
    ProcessStreamSinkSessionId,
    "session_id",
    "Checked identity of one process-stream persistence session."
);
checked_id!(
    ProcessStreamSinkSourceId,
    "source_id",
    "Checked immutable identity of the admissible source selected at open."
);
checked_id!(
    ProcessStreamSinkTerminalId,
    "terminal_id",
    "Checked identity of the one finalize/abort command permitted for a session."
);

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStreamDigestAlgorithm {
    Sha256,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStreamSinkState {
    Opening,
    Open,
    Finalizing,
    CompleteSource,
    PartialSource,
    SourceUnavailable,
    PolicyProhibited,
    RedactionFailed,
    PersistenceFailed,
    Cancelled,
    UnknownOutcome,
}

impl ProcessStreamSinkState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CompleteSource
                | Self::PartialSource
                | Self::SourceUnavailable
                | Self::PolicyProhibited
                | Self::RedactionFailed
                | Self::PersistenceFailed
                | Self::Cancelled
                | Self::UnknownOutcome
        )
    }
}

#[allow(
    clippy::struct_field_names,
    reason = "max_* names are the stable public limit schema"
)]
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkLimits {
    max_chunk_bytes: u64,
    max_total_admitted_bytes: u64,
    max_chunks: u64,
    max_preview_bytes: u64,
    max_in_flight_chunks: u32,
    max_in_flight_bytes: u64,
    max_append_wait_ms: u64,
    max_finalize_wait_ms: u64,
    max_abort_wait_ms: u64,
}

#[allow(
    clippy::struct_field_names,
    reason = "max_* names mirror the public limit schema"
)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessStreamSinkLimitsWire {
    max_chunk_bytes: u64,
    max_total_admitted_bytes: u64,
    max_chunks: u64,
    max_preview_bytes: u64,
    max_in_flight_chunks: u32,
    max_in_flight_bytes: u64,
    max_append_wait_ms: u64,
    max_finalize_wait_ms: u64,
    max_abort_wait_ms: u64,
}

impl ProcessStreamSinkLimits {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        max_chunk_bytes: u64,
        max_total_admitted_bytes: u64,
        max_chunks: u64,
        max_preview_bytes: u64,
        max_in_flight_chunks: u32,
        max_in_flight_bytes: u64,
        max_append_wait_ms: u64,
        max_finalize_wait_ms: u64,
        max_abort_wait_ms: u64,
    ) -> Result<Self, ProcessStreamSinkError> {
        if max_chunk_bytes == 0
            || max_total_admitted_bytes == 0
            || max_chunks == 0
            || max_in_flight_chunks == 0
            || max_in_flight_bytes == 0
            || max_append_wait_ms == 0
            || max_finalize_wait_ms == 0
            || max_abort_wait_ms == 0
        {
            return Err(ProcessStreamSinkError::InvalidLimits {
                reason: "all non-preview ceilings must be non-zero",
            });
        }
        if max_chunk_bytes > max_total_admitted_bytes {
            return Err(ProcessStreamSinkError::InvalidLimits {
                reason: "a chunk cannot exceed the total admitted-byte ceiling",
            });
        }
        if max_in_flight_bytes < max_chunk_bytes || max_in_flight_bytes > max_total_admitted_bytes {
            return Err(ProcessStreamSinkError::InvalidLimits {
                reason: "in-flight bytes must cover one chunk and not exceed total bytes",
            });
        }
        if max_preview_bytes > MAX_PREVIEW_BYTES {
            return Err(ProcessStreamSinkError::InvalidLimits {
                reason: "preview ceiling exceeds the evidence contract ceiling",
            });
        }
        Ok(Self {
            max_chunk_bytes,
            max_total_admitted_bytes,
            max_chunks,
            max_preview_bytes,
            max_in_flight_chunks,
            max_in_flight_bytes,
            max_append_wait_ms,
            max_finalize_wait_ms,
            max_abort_wait_ms,
        })
    }

    pub const fn max_chunk_bytes(&self) -> u64 {
        self.max_chunk_bytes
    }
    pub const fn max_total_admitted_bytes(&self) -> u64 {
        self.max_total_admitted_bytes
    }
    pub const fn max_chunks(&self) -> u64 {
        self.max_chunks
    }
    pub const fn max_preview_bytes(&self) -> u64 {
        self.max_preview_bytes
    }
    pub const fn max_in_flight_chunks(&self) -> u32 {
        self.max_in_flight_chunks
    }
    pub const fn max_in_flight_bytes(&self) -> u64 {
        self.max_in_flight_bytes
    }
    pub const fn max_append_wait_ms(&self) -> u64 {
        self.max_append_wait_ms
    }
    pub const fn max_finalize_wait_ms(&self) -> u64 {
        self.max_finalize_wait_ms
    }
    pub const fn max_abort_wait_ms(&self) -> u64 {
        self.max_abort_wait_ms
    }
}

impl<'de> Deserialize<'de> for ProcessStreamSinkLimits {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProcessStreamSinkLimitsWire::deserialize(deserializer)?;
        Self::new(
            wire.max_chunk_bytes,
            wire.max_total_admitted_bytes,
            wire.max_chunks,
            wire.max_preview_bytes,
            wire.max_in_flight_chunks,
            wire.max_in_flight_bytes,
            wire.max_append_wait_ms,
            wire.max_finalize_wait_ms,
            wire.max_abort_wait_ms,
        )
        .map_err(de::Error::custom)
    }
}
