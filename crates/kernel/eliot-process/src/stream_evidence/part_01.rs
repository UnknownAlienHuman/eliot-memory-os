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

/// Durability of the admissible source independently of preview retention.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamPersistenceStatus {
    /// The complete admissible representation is durably available.
    CompleteSource,
    /// Some exact representation is durable, but full stream coverage is not proven.
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
    /// Current policy forbids durable retention or inline disclosure of source bytes.
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

/// Coordinate system used by the bounded inline preview.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamPreviewRepresentation {
    /// Preview bytes are an exact prefix of the physical transport bytes.
    TransportBytes,
    /// Preview bytes are an exact prefix of the durable policy-transformed source.
    DurableSourceBytes,
    /// Policy permits identity/count evidence but forbids retaining inline bytes.
    WithheldByPolicy,
}

/// One omitted half-open byte interval in the selected preview representation.
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
