//! Canonical wire types for durable host-event ingest (issue #1934, I7.23).
//!
//! This additive v1 contract carries the durable-relation facts of one
//! host-event ingest record and the per-stream cursor across the bridge
//! transport: immutable transport hash, stored-bytes digest, normalized
//! envelope digest, adapter/transformation versions, disposition, redaction
//! receipt, and stream cursor. It carries digests, lengths, and dispositions
//! only: raw transport bytes and redacted projections never travel on this
//! wire, so a redacted event exposes its receipt rather than its source.
//!
//! The crate persists nothing; these types validate shape only. The durable
//! owner (`eliot-agent-acp::DurableHostEventJournal`) holds the records.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ProtocolError;

/// Stable wire identity for a durable host-event ingest record.
pub const HOST_EVENT_INGEST_RECORD_WIRE_ID: &str = "eliot.protocol.host-event-ingest-record";
/// Current durable host-event ingest record wire version.
pub const HOST_EVENT_INGEST_RECORD_WIRE_VERSION: u16 = 1;
/// Stable wire identity for a host-event stream cursor.
pub const HOST_EVENT_STREAM_CURSOR_WIRE_ID: &str = "eliot.protocol.host-event-stream-cursor";
/// Current host-event stream cursor wire version.
pub const HOST_EVENT_STREAM_CURSOR_WIRE_VERSION: u16 = 1;
/// Maximum stream identifier length in bytes.
pub const MAX_HOST_EVENT_STREAM_ID_BYTES: usize = 256;
/// Maximum redacted classes carried by one wire redaction receipt.
pub const MAX_HOST_EVENT_REDACTED_CLASSES: usize = 16;
/// Maximum version/marker text length in bytes.
pub const MAX_HOST_EVENT_INGEST_TEXT_BYTES: usize = 256;

fn bounded_text(value: &str, field: &'static str, max_bytes: usize) -> Result<(), ProtocolError> {
    if value.is_empty() || value.trim() != value {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank without surrounding whitespace",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > max_bytes {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "exceeds the bounded wire length",
        });
    }
    Ok(())
}

fn lowercase_sha256(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Durable disposition of one ingested envelope on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostEventIngestDispositionWire {
    /// Staged but not yet durably committed; cursor unadvanced.
    Staged,
    /// Raw/hash, envelope, and disposition durably related; cursor published.
    Committed,
}

/// Redaction receipt on the wire: transport hash, reason, and deterministic
/// marker. Never carries source content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostEventRedactionReceiptWire {
    /// Immutable hash of the original transport bytes.
    pub transport_hash: String,
    /// Why redaction was required (`FORBIDDEN_CONTENT_DETECTED` or
    /// `DECLARED_OUT_OF_SCOPE`).
    pub reason: String,
    /// Sorted redacted field classes.
    pub redacted_classes: Vec<String>,
    /// Deterministic projection marker.
    pub marker: String,
    /// Normalizer version that minted the redaction.
    pub normalizer_version: String,
}

impl HostEventRedactionReceiptWire {
    /// Validates the receipt shape: digests, bounded classes, and marker.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        lowercase_sha256(
            &self.transport_hash,
            "host_event_redaction_receipt.transport_hash",
        )?;
        if self.reason != "FORBIDDEN_CONTENT_DETECTED" && self.reason != "DECLARED_OUT_OF_SCOPE" {
            return Err(ProtocolError::InvalidField {
                field: "host_event_redaction_receipt.reason",
                reason: "must be a known redaction reason",
            });
        }
        if self.redacted_classes.is_empty()
            || self.redacted_classes.len() > MAX_HOST_EVENT_REDACTED_CLASSES
        {
            return Err(ProtocolError::InvalidField {
                field: "host_event_redaction_receipt.redacted_classes",
                reason: "must be nonempty and bounded",
            });
        }
        for class in &self.redacted_classes {
            bounded_text(
                class,
                "host_event_redaction_receipt.redacted_classes",
                MAX_HOST_EVENT_INGEST_TEXT_BYTES,
            )?;
        }
        bounded_text(
            &self.marker,
            "host_event_redaction_receipt.marker",
            MAX_HOST_EVENT_INGEST_TEXT_BYTES,
        )?;
        bounded_text(
            &self.normalizer_version,
            "host_event_redaction_receipt.normalizer_version",
            MAX_HOST_EVENT_INGEST_TEXT_BYTES,
        )?;
        Ok(())
    }
}

/// One durable host-event ingest record on the wire: linkage facts only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostEventIngestRecordWire {
    /// Must equal [`HOST_EVENT_INGEST_RECORD_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`HOST_EVENT_INGEST_RECORD_WIRE_VERSION`].
    pub wire_version: u16,
    /// Owning stream identifier.
    pub stream_id: String,
    /// Monotonic sequence within the stream. Must be nonzero.
    pub sequence: u64,
    /// Immutable hash of the original transport bytes.
    pub transport_hash: String,
    /// Digest of the stored bytes (raw bytes or redacted projection).
    pub stored_digest: String,
    /// Canonical digest of the normalized envelope.
    pub envelope_digest: String,
    /// True when the stored bytes are the redacted projection.
    pub redacted: bool,
    /// Adapter version that normalized the event.
    pub adapter_version: String,
    /// Transformation pipeline version.
    pub transformation_version: String,
    /// Durable disposition of the envelope.
    pub disposition: HostEventIngestDispositionWire,
    /// Number of state applications (0 or 1).
    pub applied_count: u32,
    /// True once acknowledged at or past this sequence.
    pub acked: bool,
    /// Present exactly when `redacted` is true.
    pub redaction: Option<HostEventRedactionReceiptWire>,
}

impl HostEventIngestRecordWire {
    /// Validates wire identity, linkage digests, versions, disposition
    /// coherence, and the redaction presence invariant.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != HOST_EVENT_INGEST_RECORD_WIRE_ID {
            return Err(ProtocolError::InvalidField {
                field: "host_event_ingest_record.wire_id",
                reason: "must be the durable ingest record wire identity",
            });
        }
        if self.wire_version != HOST_EVENT_INGEST_RECORD_WIRE_VERSION {
            return Err(ProtocolError::InvalidField {
                field: "host_event_ingest_record.wire_version",
                reason: "must be the current durable ingest wire version",
            });
        }
        bounded_text(
            &self.stream_id,
            "host_event_ingest_record.stream_id",
            MAX_HOST_EVENT_STREAM_ID_BYTES,
        )?;
        if self.sequence == 0 {
            return Err(ProtocolError::InvalidField {
                field: "host_event_ingest_record.sequence",
                reason: "must be nonzero",
            });
        }
        lowercase_sha256(
            &self.transport_hash,
            "host_event_ingest_record.transport_hash",
        )?;
        lowercase_sha256(
            &self.stored_digest,
            "host_event_ingest_record.stored_digest",
        )?;
        lowercase_sha256(
            &self.envelope_digest,
            "host_event_ingest_record.envelope_digest",
        )?;
        bounded_text(
            &self.adapter_version,
            "host_event_ingest_record.adapter_version",
            MAX_HOST_EVENT_INGEST_TEXT_BYTES,
        )?;
        bounded_text(
            &self.transformation_version,
            "host_event_ingest_record.transformation_version",
            MAX_HOST_EVENT_INGEST_TEXT_BYTES,
        )?;
        if self.applied_count > 1 {
            return Err(ProtocolError::InvalidField {
                field: "host_event_ingest_record.applied_count",
                reason: "duplicates never re-apply, so at most one application exists",
            });
        }
        match (&self.redaction, self.redacted) {
            (Some(receipt), true) => {
                receipt.validate()?;
                if receipt.transport_hash != self.transport_hash {
                    return Err(ProtocolError::InvalidField {
                        field: "host_event_ingest_record.redaction.transport_hash",
                        reason: "must equal the record transport hash",
                    });
                }
            }
            (None, false) => {}
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "host_event_ingest_record.redaction",
                    reason: "must be present exactly for redacted records",
                });
            }
        }
        Ok(())
    }
}

/// Per-stream cursor on the wire, separate from turn and process state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostEventStreamCursorWire {
    /// Must equal [`HOST_EVENT_STREAM_CURSOR_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`HOST_EVENT_STREAM_CURSOR_WIRE_VERSION`].
    pub wire_version: u16,
    /// Owning stream identifier.
    pub stream_id: String,
    /// Last durably committed sequence.
    pub last_durable_sequence: u64,
    /// Last acknowledged sequence. Never exceeds the durable cursor.
    pub last_acked_sequence: u64,
}

impl HostEventStreamCursorWire {
    /// Validates wire identity and the acked-at-most-durable invariant.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != HOST_EVENT_STREAM_CURSOR_WIRE_ID {
            return Err(ProtocolError::InvalidField {
                field: "host_event_stream_cursor.wire_id",
                reason: "must be the stream cursor wire identity",
            });
        }
        if self.wire_version != HOST_EVENT_STREAM_CURSOR_WIRE_VERSION {
            return Err(ProtocolError::InvalidField {
                field: "host_event_stream_cursor.wire_version",
                reason: "must be the current stream cursor wire version",
            });
        }
        bounded_text(
            &self.stream_id,
            "host_event_stream_cursor.stream_id",
            MAX_HOST_EVENT_STREAM_ID_BYTES,
        )?;
        if self.last_acked_sequence > self.last_durable_sequence {
            return Err(ProtocolError::InvalidField {
                field: "host_event_stream_cursor.last_acked_sequence",
                reason: "acknowledgement cannot reach past the durable cursor",
            });
        }
        Ok(())
    }
}
