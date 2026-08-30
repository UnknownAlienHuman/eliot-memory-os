//! Provider-neutral contract for durable process-stream evidence.
//!
//! This module owns only the immutable stdout/stderr evidence description and
//! its fail-closed validation. It does not own process execution, `BlobStore`,
//! ORS, parsing, evaluation, canonical admission, or task completion.

use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

use super::ProcessExecutionBinding;

/// Current wire revision for one stdout/stderr evidence description.
pub const PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION: &str =
    "eliot-process-stream-evidence-v1";

const MAX_REFERENCE_BYTES: usize = 2_048;
const MAX_PREVIEW_BYTES: usize = 16 * 1024 * 1024;
const MAX_GAPS: usize = 16;

/// Physical stream owned by one process operation.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStreamKind {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Whether the physical stream transport reached an exact terminal boundary.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamTransportStatus {
    /// EOF was observed after every received byte was drained.
    Complete,
    /// A read failed after zero or more bytes were observed.
    ReadFailed,
    /// Cancellation ended capture before EOF was observed.
    CancelledBeforeEof,
    /// The requested stream handle/capture route was unavailable.
    CaptureUnavailable,
    /// The transport outcome itself cannot be established.
    UnknownOutcome,
}

/// Durability of the exact source bytes independently of preview retention.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamPersistenceStatus {
    /// The complete observed stream is durably available under an immutable locator.
    CompleteSource,
    /// Some exact bytes are durable, but full process-stream coverage is not proven.
    PartialSource,
    /// No durable expansion source is available.
    SourceUnavailable,
}

/// Parsing remains independent from capture and persistence.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamParsingStatus {
    /// Raw bytes only; no parser claim exists.
    Raw,
    /// A downstream parser accepted the declared source.
    Parsed,
    /// A downstream parser ran and failed.
    ParseFailed,
    /// Parsing does not apply to the declared evidence use.
    NotApplicable,
}

/// Evaluation remains independent from execution, capture, persistence and parsing.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamEvaluationStatus {
    /// No Evaluation Contract has assessed the stream.
    Unassessed,
    /// A downstream evaluator passed the declared property.
    Pass,
    /// A downstream evaluator failed the declared property.
    Fail,
    /// Evaluation ran but could not establish pass/fail.
    Inconclusive,
    /// The prior evaluation no longer applies to the current fence or source.
    Stale,
}

/// Exact reason why complete durable source coverage is unavailable.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamEvidenceGap {
    /// Current policy forbids durable retention of the exact source.
    PolicyProhibited,
    /// The configured persistence provider was unavailable.
    PersistenceUnavailable,
    /// Persistence could not keep up while the executor still had to drain the pipe.
    PersistenceBackpressure,
    /// Persistence returned a known failure.
    PersistenceFailed,
    /// Persistence may or may not have committed the source.
    PersistenceUnknownOutcome,
    /// Required redaction/transformation could not produce an admissible exact source.
    RedactionFailed,
    /// Physical reading failed before EOF.
    TransportReadFailed,
    /// Cancellation ended the stream before EOF.
    CancelledBeforeEof,
    /// No stream capture route was available.
    CaptureUnavailable,
    /// Physical stream completion cannot be established.
    UnknownOutcome,
}

/// One omitted half-open byte interval in the observed stream.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct StreamByteRange {
    start: u64,
    end_exclusive: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamByteRangeWire {
    start: u64,
    end_exclusive: u64,
}

impl StreamByteRange {
    /// Creates a non-empty half-open range.
    pub const fn new(start: u64, end_exclusive: u64) -> Result<Self, ProcessStreamEvidenceError> {
        if start >= end_exclusive {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "omitted_range",
                reason: "start must precede end_exclusive",
            });
        }
        Ok(Self {
            start,
            end_exclusive,
        })
    }

    /// First omitted byte offset.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Exclusive end offset.
    pub const fn end_exclusive(&self) -> u64 {
        self.end_exclusive
    }
}

impl<'de> Deserialize<'de> for StreamByteRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = StreamByteRangeWire::deserialize(deserializer)?;
        Self::new(wire.start, wire.end_exclusive).map_err(de::Error::custom)
    }
}

/// Policy identities fixed before stream bytes are offered to persistence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProcessStreamPolicyBinding {
    policy_ref: String,
    privacy_ref: String,
    visibility_ref: String,
    retention_ref: String,
    redaction_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessStreamPolicyBindingWire {
    policy_ref: String,
    privacy_ref: String,
    visibility_ref: String,
    retention_ref: String,
    redaction_ref: String,
}

impl ProcessStreamPolicyBinding {
    /// Creates the exact policy/retention/disclosure binding applied before persistence.
    pub fn new(
        policy_ref: impl Into<String>,
        privacy_ref: impl Into<String>,
        visibility_ref: impl Into<String>,
        retention_ref: impl Into<String>,
        redaction_ref: impl Into<String>,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        let value = Self {
            policy_ref: policy_ref.into(),
            privacy_ref: privacy_ref.into(),
            visibility_ref: visibility_ref.into(),
            retention_ref: retention_ref.into(),
            redaction_ref: redaction_ref.into(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProcessStreamEvidenceError> {
        for (field, value) in [
            ("policy_ref", self.policy_ref.as_str()),
            ("privacy_ref", self.privacy_ref.as_str()),
            ("visibility_ref", self.visibility_ref.as_str()),
            ("retention_ref", self.retention_ref.as_str()),
            ("redaction_ref", self.redaction_ref.as_str()),
        ] {
            validate_reference(field, value)?;
        }
        Ok(())
    }

    /// Governing policy snapshot/decision reference.
    pub fn policy_ref(&self) -> &str {
        &self.policy_ref
    }

    /// Privacy classification/reference.
    pub fn privacy_ref(&self) -> &str {
        &self.privacy_ref
    }

    /// Visibility/disclosure reference.
    pub fn visibility_ref(&self) -> &str {
        &self.visibility_ref
    }

    /// Retention/erasure reference.
    pub fn retention_ref(&self) -> &str {
        &self.retention_ref
    }

    /// Exact redaction/transformation profile reference.
    pub fn redaction_ref(&self) -> &str {
        &self.redaction_ref
    }
}

impl<'de> Deserialize<'de> for ProcessStreamPolicyBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProcessStreamPolicyBindingWire::deserialize(deserializer)?;
        Self::new(
            wire.policy_ref,
            wire.privacy_ref,
            wire.visibility_ref,
            wire.retention_ref,
            wire.redaction_ref,
        )
        .map_err(de::Error::custom)
    }
}

/// Bounded in-record prefix preview, distinct from the durable exact source.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProcessStreamPrefixPreview {
    bytes: Vec<u8>,
    sha256: String,
    retained_bytes: u64,
    observed_bytes: u64,
    omitted_ranges: Vec<StreamByteRange>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessStreamPrefixPreviewWire {
    bytes: Vec<u8>,
    sha256: String,
    retained_bytes: u64,
    observed_bytes: u64,
    omitted_ranges: Vec<StreamByteRange>,
}

impl ProcessStreamPrefixPreview {
    /// Builds the canonical prefix preview for the number of bytes observed so far.
    pub fn from_prefix(
        bytes: Vec<u8>,
        observed_bytes: u64,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        if bytes.len() > MAX_PREVIEW_BYTES {
            return Err(ProcessStreamEvidenceError::LimitExceeded {
                field: "preview.bytes",
                limit: MAX_PREVIEW_BYTES,
            });
        }
        let retained_bytes = u64::try_from(bytes.len()).map_err(|_| {
            ProcessStreamEvidenceError::Invariant {
                field: "preview.retained_bytes",
                reason: "preview length does not fit u64",
            }
        })?;
        if retained_bytes > observed_bytes {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.observed_bytes",
                reason: "observed bytes cannot be smaller than retained bytes",
            });
        }
        let omitted_ranges = if retained_bytes == observed_bytes {
            Vec::new()
        } else {
            vec![StreamByteRange::new(retained_bytes, observed_bytes)?]
        };
        Ok(Self {
            sha256: sha256_hex(&bytes),
            bytes,
            retained_bytes,
            observed_bytes,
            omitted_ranges,
        })
    }

    fn validate(&self) -> Result<(), ProcessStreamEvidenceError> {
        if self.bytes.len() > MAX_PREVIEW_BYTES {
            return Err(ProcessStreamEvidenceError::LimitExceeded {
                field: "preview.bytes",
                limit: MAX_PREVIEW_BYTES,
            });
        }
        let retained_bytes = u64::try_from(self.bytes.len()).map_err(|_| {
            ProcessStreamEvidenceError::Invariant {
                field: "preview.retained_bytes",
                reason: "preview length does not fit u64",
            }
        })?;
        if self.retained_bytes != retained_bytes || self.retained_bytes > self.observed_bytes {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.byte_counts",
                reason: "retained/observed byte counts are inconsistent",
            });
        }
        validate_digest("preview.sha256", &self.sha256)?;
        if self.sha256 != sha256_hex(&self.bytes) {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.sha256",
                reason: "digest does not match retained preview bytes",
            });
        }
        let expected = if self.retained_bytes == self.observed_bytes {
            Vec::new()
        } else {
            vec![StreamByteRange::new(
                self.retained_bytes,
                self.observed_bytes,
            )?]
        };
        if self.omitted_ranges != expected {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview.omitted_ranges",
                reason: "prefix preview must expose the exact omitted suffix",
            });
        }
        Ok(())
    }

    /// Retained preview bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 over retained preview bytes only.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Number of retained bytes.
    pub const fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    /// Number of bytes observed from the transport.
    pub const fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }

    /// Exact ranges omitted from the prefix preview.
    pub fn omitted_ranges(&self) -> &[StreamByteRange] {
        &self.omitted_ranges
    }

    /// Whether the preview omits any observed bytes.
    pub const fn is_truncated(&self) -> bool {
        self.retained_bytes < self.observed_bytes
    }
}

impl<'de> Deserialize<'de> for ProcessStreamPrefixPreview {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProcessStreamPrefixPreviewWire::deserialize(deserializer)?;
        let value = Self {
            bytes: wire.bytes,
            sha256: wire.sha256,
            retained_bytes: wire.retained_bytes,
            observed_bytes: wire.observed_bytes,
            omitted_ranges: wire.omitted_ranges,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Closed locator class for immutable expansion sources; synthetic `raw:` handles
/// are intentionally not representable.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableStreamLocatorKind {
    /// Provider-neutral BlobStore object/receipt.
    Blob,
    /// Another admitted immutable artifact/evidence store.
    ImmutableArtifact,
}

/// Relationship between durable bytes and the physical transport stream.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableStreamRepresentation {
    /// The stored bytes are exactly the transport bytes in the declared coverage interval.
    ExactTransportBytes,
    /// The stored bytes are the exact output of the declared policy transformation.
    PolicyTransformed,
}

/// Durable exact bytes plus the receipt needed to resolve and verify them.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DurableProcessStreamSource {
    kind: DurableStreamLocatorKind,
    representation: DurableStreamRepresentation,
    locator: String,
    ready_receipt_ref: String,
    sha256: String,
    byte_length: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableProcessStreamSourceWire {
    kind: DurableStreamLocatorKind,
    representation: DurableStreamRepresentation,
    locator: String,
    ready_receipt_ref: String,
    sha256: String,
    byte_length: u64,
}

impl DurableProcessStreamSource {
    /// Creates one immutable expansion source. Zero-byte sources are valid.
    pub fn new(
        kind: DurableStreamLocatorKind,
        representation: DurableStreamRepresentation,
        locator: impl Into<String>,
        ready_receipt_ref: impl Into<String>,
        sha256: impl Into<String>,
        byte_length: u64,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        let value = Self {
            kind,
            representation,
            locator: locator.into(),
            ready_receipt_ref: ready_receipt_ref.into(),
            sha256: sha256.into(),
            byte_length,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProcessStreamEvidenceError> {
        validate_reference("source.locator", &self.locator)?;
        let lower = self.locator.to_ascii_lowercase();
        if lower.starts_with("raw:") || lower.starts_with("memory:") {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "source.locator",
                reason: "synthetic or process-memory locators are forbidden",
            });
        }
        validate_reference("source.ready_receipt_ref", &self.ready_receipt_ref)?;
        validate_digest("source.sha256", &self.sha256)
    }

    /// Locator class.
    pub const fn kind(&self) -> DurableStreamLocatorKind {
        self.kind
    }

    /// Relationship between stored bytes and transport bytes.
    pub const fn representation(&self) -> DurableStreamRepresentation {
        self.representation
    }

    /// Immutable locator.
    pub fn locator(&self) -> &str {
        &self.locator
    }

    /// Receipt proving the locator is durably ready.
    pub fn ready_receipt_ref(&self) -> &str {
        &self.ready_receipt_ref
    }

    /// SHA-256 over the exact durable source bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Exact durable source length.
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

impl<'de> Deserialize<'de> for DurableProcessStreamSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = DurableProcessStreamSourceWire::deserialize(deserializer)?;
        Self::new(
            wire.kind,
            wire.representation,
            wire.locator,
            wire.ready_receipt_ref,
            wire.sha256,
            wire.byte_length,
        )
        .map_err(de::Error::custom)
    }
}

/// Immutable raw stream evidence bound to one exact process operation and policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProcessStreamEvidence {
    schema_version: String,
    binding: ProcessExecutionBinding,
    stream: ProcessStreamKind,
    policy: ProcessStreamPolicyBinding,
    transport: StreamTransportStatus,
    persistence: StreamPersistenceStatus,
    observed_sha256: String,
    preview: ProcessStreamPrefixPreview,
    source: Option<DurableProcessStreamSource>,
    gaps: Vec<StreamEvidenceGap>,
    parsing: StreamParsingStatus,
    evaluation: StreamEvaluationStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessStreamEvidenceWire {
    schema_version: String,
    binding: ProcessExecutionBinding,
    stream: ProcessStreamKind,
    policy: ProcessStreamPolicyBinding,
    transport: StreamTransportStatus,
    persistence: StreamPersistenceStatus,
    observed_sha256: String,
    preview: ProcessStreamPrefixPreview,
    source: Option<DurableProcessStreamSource>,
    gaps: Vec<StreamEvidenceGap>,
    parsing: StreamParsingStatus,
    evaluation: StreamEvaluationStatus,
}

impl ProcessStreamEvidence {
    /// Creates raw capture evidence. Parsing/evaluation cannot be promoted here.
    #[allow(clippy::too_many_arguments)]
    pub fn new_raw(
        binding: ProcessExecutionBinding,
        stream: ProcessStreamKind,
        policy: ProcessStreamPolicyBinding,
        transport: StreamTransportStatus,
        persistence: StreamPersistenceStatus,
        observed_sha256: impl Into<String>,
        preview: ProcessStreamPrefixPreview,
        source: Option<DurableProcessStreamSource>,
        gaps: Vec<StreamEvidenceGap>,
    ) -> Result<Self, ProcessStreamEvidenceError> {
        let mut gaps = gaps;
        gaps.sort_unstable();
        let value = Self {
            schema_version: PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION.to_owned(),
            binding,
            stream,
            policy,
            transport,
            persistence,
            observed_sha256: observed_sha256.into(),
            preview,
            source,
            gaps,
            parsing: StreamParsingStatus::Raw,
            evaluation: StreamEvaluationStatus::Unassessed,
        };
        value.validate()?;
        Ok(value)
    }

    /// Revalidates all binding, preview, persistence and status invariants.
    pub fn validate(&self) -> Result<(), ProcessStreamEvidenceError> {
        if self.schema_version != PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "schema_version",
                reason: "unsupported process-stream evidence revision",
            });
        }
        self.binding
            .validate()
            .map_err(|_| ProcessStreamEvidenceError::InvalidBinding)?;
        self.policy.validate()?;
        self.preview.validate()?;
        validate_digest("observed_sha256", &self.observed_sha256)?;
        if !self.preview.is_truncated() && self.observed_sha256 != self.preview.sha256 {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "observed_sha256",
                reason: "untruncated preview must identify all observed transport bytes",
            });
        }
        if let Some(source) = &self.source {
            source.validate()?;
        }
        if self.gaps.len() > MAX_GAPS {
            return Err(ProcessStreamEvidenceError::LimitExceeded {
                field: "gaps",
                limit: MAX_GAPS,
            });
        }
        let unique = self.gaps.iter().copied().collect::<BTreeSet<_>>();
        if unique.len() != self.gaps.len() {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "gaps",
                reason: "gap reasons must be unique",
            });
        }
        if !self.gaps.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "gaps",
                reason: "gap reasons must use canonical sorted order",
            });
        }
        if self.parsing != StreamParsingStatus::Raw
            || self.evaluation != StreamEvaluationStatus::Unassessed
        {
            return Err(ProcessStreamEvidenceError::AuthorityEscalation);
        }
        self.validate_transport_gaps(&unique)?;
        self.validate_persistence(&unique)
    }

    fn validate_transport_gaps(
        &self,
        gaps: &BTreeSet<StreamEvidenceGap>,
    ) -> Result<(), ProcessStreamEvidenceError> {
        let required = match self.transport {
            StreamTransportStatus::Complete => None,
            StreamTransportStatus::ReadFailed => Some(StreamEvidenceGap::TransportReadFailed),
            StreamTransportStatus::CancelledBeforeEof => {
                Some(StreamEvidenceGap::CancelledBeforeEof)
            }
            StreamTransportStatus::CaptureUnavailable => {
                Some(StreamEvidenceGap::CaptureUnavailable)
            }
            StreamTransportStatus::UnknownOutcome => Some(StreamEvidenceGap::UnknownOutcome),
        };
        if required.is_some_and(|reason| !gaps.contains(&reason)) {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "transport",
                reason: "non-complete transport requires its exact coverage gap",
            });
        }
        if self.transport == StreamTransportStatus::CaptureUnavailable
            && (self.preview.retained_bytes != 0 || self.preview.observed_bytes != 0)
        {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "preview",
                reason: "capture-unavailable transport cannot claim observed bytes",
            });
        }
        if self.transport == StreamTransportStatus::CaptureUnavailable
            && self.persistence != StreamPersistenceStatus::SourceUnavailable
        {
            return Err(ProcessStreamEvidenceError::Invariant {
                field: "persistence",
                reason: "capture-unavailable transport cannot publish a durable source",
            });
        }
        Ok(())
    }

    fn validate_persistence(
        &self,
        gaps: &BTreeSet<StreamEvidenceGap>,
    ) -> Result<(), ProcessStreamEvidenceError> {
        match self.persistence {
            StreamPersistenceStatus::CompleteSource => {
                let source = self.source.as_ref().ok_or(
                    ProcessStreamEvidenceError::Invariant {
                        field: "source",
                        reason: "complete source requires an immutable locator and ready receipt",
                    },
                )?;
                if self.transport != StreamTransportStatus::Complete || !gaps.is_empty() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "persistence",
                        reason: "complete source requires EOF and no coverage gaps",
                    });
                }
                if source.representation == DurableStreamRepresentation::ExactTransportBytes
                    && (source.byte_length != self.preview.observed_bytes
                        || source.sha256 != self.observed_sha256)
                {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "source",
                        reason: "complete exact source must identify all observed transport bytes",
                    });
                }
            }
            StreamPersistenceStatus::PartialSource => {
                let source = self.source.as_ref().ok_or(
                    ProcessStreamEvidenceError::Invariant {
                        field: "source",
                        reason: "partial source requires an immutable locator and ready receipt",
                    },
                )?;
                if gaps.is_empty() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "gaps",
                        reason: "partial source requires an explicit coverage gap",
                    });
                }
                if source.representation == DurableStreamRepresentation::ExactTransportBytes {
                    if source.byte_length > self.preview.observed_bytes {
                        return Err(ProcessStreamEvidenceError::Invariant {
                            field: "source.byte_length",
                            reason: "exact durable bytes cannot exceed observed transport bytes",
                        });
                    }
                    if source.byte_length == self.preview.observed_bytes
                        && source.sha256 == self.observed_sha256
                        && self.transport == StreamTransportStatus::Complete
                    {
                        return Err(ProcessStreamEvidenceError::Invariant {
                            field: "persistence",
                            reason: "full durable EOF coverage must be COMPLETE_SOURCE",
                        });
                    }
                }
            }
            StreamPersistenceStatus::SourceUnavailable => {
                if self.source.is_some() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "source",
                        reason: "source-unavailable evidence cannot carry a durable locator",
                    });
                }
                if gaps.is_empty() {
                    return Err(ProcessStreamEvidenceError::Invariant {
                        field: "gaps",
                        reason: "source-unavailable evidence requires an exact reason",
                    });
                }
            }
        }
        Ok(())
    }

    /// Content identity over the complete typed evidence description.
    pub fn identity_sha256(&self) -> Result<String, ProcessStreamEvidenceError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| ProcessStreamEvidenceError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Exact process/authority binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Stdout or stderr.
    pub const fn stream(&self) -> ProcessStreamKind {
        self.stream
    }

    /// Policy fixed before persistence.
    pub const fn policy(&self) -> &ProcessStreamPolicyBinding {
        &self.policy
    }

    /// Physical capture completion.
    pub const fn transport(&self) -> StreamTransportStatus {
        self.transport
    }

    /// Exact source durability.
    pub const fn persistence(&self) -> StreamPersistenceStatus {
        self.persistence
    }

    /// SHA-256 over every byte physically observed, including omitted preview bytes.
    pub fn observed_sha256(&self) -> &str {
        &self.observed_sha256
    }

    /// Bounded prefix preview.
    pub const fn preview(&self) -> &ProcessStreamPrefixPreview {
        &self.preview
    }

    /// Immutable expansion source, when available.
    pub const fn source(&self) -> Option<&DurableProcessStreamSource> {
        self.source.as_ref()
    }

    /// Coverage gaps.
    pub fn gaps(&self) -> &[StreamEvidenceGap] {
        &self.gaps
    }

    /// Parsing status. Raw ProcessExecutor evidence is always `RAW`.
    pub const fn parsing(&self) -> StreamParsingStatus {
        self.parsing
    }

    /// Evaluation status. Raw ProcessExecutor evidence is always `UNASSESSED`.
    pub const fn evaluation(&self) -> StreamEvaluationStatus {
        self.evaluation
    }
}

impl<'de> Deserialize<'de> for ProcessStreamEvidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ProcessStreamEvidenceWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            binding: wire.binding,
            stream: wire.stream,
            policy: wire.policy,
            transport: wire.transport,
            persistence: wire.persistence,
            observed_sha256: wire.observed_sha256,
            preview: wire.preview,
            source: wire.source,
            gaps: wire.gaps,
            parsing: wire.parsing,
            evaluation: wire.evaluation,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Typed contract failure; no raw stream or secret content is included.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProcessStreamEvidenceError {
    /// A reference is missing, contains controls or exceeds its bound.
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

fn validate_reference(
    field: &'static str,
    value: &str,
) -> Result<(), ProcessStreamEvidenceError> {
    if value.trim().is_empty()
        || value.len() > MAX_REFERENCE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ProcessStreamEvidenceError::InvalidReference { field });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActionLeaseRef, DispatchAuthorityId, FencingToken, Generation, ImageId, JobId, OperationId,
        ProcessTreeId, SessionId,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn binding() -> TestResult<ProcessExecutionBinding> {
        let generation = Generation::new(3)?;
        Ok(ProcessExecutionBinding {
            operation_id: OperationId::new("operation-1")?,
            process_tree_id: ProcessTreeId::new("tree-1")?,
            job_id: JobId::new("job-1")?,
            image_id: ImageId::new("image-1")?,
            session_id: SessionId::new("session-1")?,
            generation,
            action_lease_ref: ActionLeaseRef::new("lease-1")?,
            authority_id: DispatchAuthorityId::new("authority-1")?,
            authority_epoch: 7,
            state_fence: FencingToken::new(7, generation, "fence-1")?,
            request_digest: "a".repeat(64),
            permit_digest: "b".repeat(64),
            effect_digest: "c".repeat(64),
            validation_revision: 2,
        })
    }

    fn policy() -> Result<ProcessStreamPolicyBinding, ProcessStreamEvidenceError> {
        ProcessStreamPolicyBinding::new(
            "policy:1",
            "privacy:project",
            "visibility:owner",
            "retention:task",
            "redaction:exact-v1",
        )
    }

    fn source(bytes: &[u8]) -> Result<DurableProcessStreamSource, ProcessStreamEvidenceError> {
        let digest = sha256_hex(bytes);
        let byte_length = u64::try_from(bytes.len()).map_err(|_| {
            ProcessStreamEvidenceError::Invariant {
                field: "test.source.byte_length",
                reason: "test source length does not fit u64",
            }
        })?;
        DurableProcessStreamSource::new(
            DurableStreamLocatorKind::Blob,
            DurableStreamRepresentation::ExactTransportBytes,
            format!("eliot://blob/{digest}"),
            format!("receipt:blob-ready:{digest}"),
            digest,
            byte_length,
        )
    }

    #[test]
    fn truncated_preview_and_complete_source_keep_separate_identities() -> TestResult {
        let preview = ProcessStreamPrefixPreview::from_prefix(b"abc".to_vec(), 6)?;
        let source = source(b"abcdef")?;
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abcdef"),
            preview,
            Some(source),
            Vec::new(),
        )?;
        assert!(evidence.preview().is_truncated());
        assert_ne!(
            evidence.preview().sha256(),
            evidence.source().ok_or("missing source")?.sha256()
        );
        assert_eq!(evidence.source().ok_or("missing source")?.byte_length(), 6);
        Ok(())
    }

    #[test]
    fn zero_byte_complete_stream_is_valid() -> TestResult {
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stderr,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(&[]),
            ProcessStreamPrefixPreview::from_prefix(Vec::new(), 0)?,
            Some(source(&[])?),
            Vec::new(),
        )?;
        assert_eq!(evidence.preview().observed_bytes(), 0);
        assert_eq!(evidence.source().ok_or("missing source")?.byte_length(), 0);
        Ok(())
    }

    #[test]
    fn complete_source_requires_durable_locator() -> TestResult {
        let result = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            ProcessStreamPrefixPreview::from_prefix(b"abc".to_vec(), 3)?,
            None,
            Vec::new(),
        );
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn synthetic_raw_locator_is_rejected() {
        let result = DurableProcessStreamSource::new(
            DurableStreamLocatorKind::ImmutableArtifact,
            DurableStreamRepresentation::ExactTransportBytes,
            "raw:p04-stream:sha256:abc",
            "receipt:ready",
            "a".repeat(64),
            3,
        );
        assert!(result.is_err());
    }

    #[test]
    fn read_failure_can_only_publish_partial_source() -> TestResult {
        let preview = ProcessStreamPrefixPreview::from_prefix(b"abc".to_vec(), 3)?;
        let complete = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::ReadFailed,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            preview.clone(),
            Some(source(b"abc")?),
            vec![StreamEvidenceGap::TransportReadFailed],
        );
        assert!(complete.is_err());

        let partial = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::ReadFailed,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(b"abc"),
            preview,
            Some(source(b"abc")?),
            vec![StreamEvidenceGap::TransportReadFailed],
        )?;
        assert_eq!(partial.persistence(), StreamPersistenceStatus::PartialSource);
        Ok(())
    }

    #[test]
    fn unavailable_source_requires_reason_and_no_locator() -> TestResult {
        let preview = ProcessStreamPrefixPreview::from_prefix(b"abc".to_vec(), 3)?;
        let no_gap = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            sha256_hex(b"abc"),
            preview.clone(),
            None,
            Vec::new(),
        );
        assert!(no_gap.is_err());

        let with_locator = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            sha256_hex(b"abc"),
            preview.clone(),
            Some(source(b"abc")?),
            vec![StreamEvidenceGap::PersistenceUnavailable],
        );
        assert!(with_locator.is_err());

        let unavailable = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            sha256_hex(b"abc"),
            preview,
            None,
            vec![StreamEvidenceGap::PolicyProhibited],
        )?;
        assert!(unavailable.source().is_none());
        Ok(())
    }

    #[test]
    fn stdout_and_stderr_have_distinct_typed_identities() -> TestResult {
        let preview = ProcessStreamPrefixPreview::from_prefix(b"abc".to_vec(), 3)?;
        let stdout = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            preview.clone(),
            Some(source(b"abc")?),
            Vec::new(),
        )?;
        let stderr = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stderr,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            preview,
            Some(source(b"abc")?),
            Vec::new(),
        )?;
        assert_ne!(stdout.identity_sha256()?, stderr.identity_sha256()?);
        Ok(())
    }

    #[test]
    fn deserialization_rejects_parser_or_evaluator_promotion() -> TestResult {
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            ProcessStreamPrefixPreview::from_prefix(b"abc".to_vec(), 3)?,
            Some(source(b"abc")?),
            Vec::new(),
        )?;
        let mut value = serde_json::to_value(evidence)?;
        value["parsing"] = serde_json::json!("PARSED");
        value["evaluation"] = serde_json::json!("PASS");
        assert!(serde_json::from_value::<ProcessStreamEvidence>(value).is_err());
        Ok(())
    }
}
