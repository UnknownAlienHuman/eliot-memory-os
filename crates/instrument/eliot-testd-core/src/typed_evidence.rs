//! Typed process-stream evidence consumer contract (issue #456, Wave A).
//!
//! Owner-neutral admission of [`ProcessStreamEvidence`](eliot_process::ProcessStreamEvidence)
//! emitted by the physical `ProcessExecutor`. Testd may parse, normalize,
//! evaluate, or cite process output only after consuming the typed stream
//! value, resolving its immutable source through the injected
//! [`ProcessStreamSourceReadbackPort`], and verifying the readback
//! locator/receipt/digest/length binding itself. Process exit, a legacy
//! string handle, a bounded preview, or caller-supplied bytes can never
//! impersonate complete raw evidence or a verifier result.
//!
//! Boundaries kept by this module:
//!
//! - no Blob/filesystem access: source bytes arrive only through the injected
//!   port, and the [`Debug`] projections below never render raw bytes;
//! - a resolved byte buffer is ephemeral parser input
//!   ([`EphemeralSourceBytes`]); the durable [`TestdStreamEvidenceBinding`]
//!   and [`VerificationReceipt`](super::VerificationReceipt) keep immutable
//!   source and readback bindings, never an unbounded byte duplicate;
//! - legacy references are retained as provenance only and can never be
//!   upgraded by supplying matching bytes later;
//! - process execution, stream transport, source persistence, parsing, and
//!   evaluation remain separate closed axes: admitting a stream sets no
//!   parser/evaluator status, and parser success sets no evaluator status.

use eliot_contracts::{ClockReading, StateFence};
use eliot_process::{
    DurableStreamLocatorKind, DurableStreamRepresentation, ProcessEvidence,
    ProcessExecutionBinding, ProcessStreamEvidence, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamTransformationBinding, StreamEvidenceGap, StreamPersistenceStatus,
    StreamTransportStatus,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{TestdError, sha256_hex};

/// Maximum retained coverage gaps per stream binding.
///
/// The provider gap vocabulary is closed and unique, so this bound only
/// rejects corrupt records; it never truncates admitted evidence.
const MAX_BINDING_GAPS: usize = 16;
/// Maximum length of a retained locator/reference/identity string.
const MAX_BINDING_REFERENCE_BYTES: usize = 4096;

/// Typed evidence errors (issue #456 `[errors]`).
///
/// Every variant carries a stable machine-readable code. Partial,
/// unavailable, policy-prohibited, redaction-failed, purged, stale, corrupt,
/// and unknown sources remain distinct: no variant collapses two of them.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum TestdEvidenceError {
    /// A stream binding disagrees with its enclosing record, or admitted
    /// evidence is internally incoherent.
    #[error("PROCESS_EVIDENCE_BINDING_MISMATCH: {reason}")]
    BindingMismatch {
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// A requested stream has no explicit disposition, or a partial claim
    /// carries no explicit gaps.
    #[error("STREAM_DENOMINATOR_INCOMPLETE: {reason}")]
    DenominatorIncomplete {
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// The stream has no durable expansion source.
    #[error("STREAM_SOURCE_UNAVAILABLE: {reason}")]
    SourceUnavailable {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// The durable source covers only part of the stream.
    #[error("STREAM_SOURCE_PARTIAL: {reason}")]
    SourcePartial {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that produced the partial outcome.
        reason: &'static str,
    },
    /// Policy forbids durable retention or disclosure of the source bytes.
    #[error("STREAM_SOURCE_POLICY_PROHIBITED: {reason}")]
    SourcePolicyProhibited {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// Required redaction/transformation could not produce an admissible
    /// exact source.
    #[error("STREAM_SOURCE_REDACTION_FAILED: {reason}")]
    SourceRedactionFailed {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// The source was purged after the stream was admitted.
    #[error("STREAM_SOURCE_PURGED: {reason}")]
    SourcePurged {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// Retention policy blocks readback of the admitted source.
    #[error("STREAM_SOURCE_RETENTION_BLOCKED: {reason}")]
    SourceRetentionBlocked {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// Readback bytes do not match the admitted source identity.
    #[error("STREAM_SOURCE_INTEGRITY_BROKEN: {reason}")]
    SourceIntegrityBroken {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// The source or its fence no longer applies to the current attempt.
    #[error("STREAM_SOURCE_STALE: {reason}")]
    SourceStale {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// The source outcome itself cannot be established.
    #[error("STREAM_SOURCE_UNKNOWN_OUTCOME: {reason}")]
    SourceUnknownOutcome {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// The readback observation names a different locator, ready receipt, or
    /// fence than the admitted source.
    #[error("STREAM_READBACK_IDENTITY_MISMATCH: {reason}")]
    ReadbackIdentityMismatch {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// The readback digest disagrees with the admitted source digest.
    #[error("STREAM_READBACK_DIGEST_MISMATCH: {reason}")]
    ReadbackDigestMismatch {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// The readback length disagrees with the admitted source length.
    #[error("STREAM_READBACK_LENGTH_MISMATCH: {reason}")]
    ReadbackLengthMismatch {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// No parser executed on the admitted source.
    #[error("PARSER_NOT_EXECUTED")]
    ParserNotExecuted {
        /// Affected physical stream.
        stream: ProcessStreamKind,
    },
    /// The parsing observation does not apply to the admitted source.
    #[error("PARSER_INCOMPATIBLE: {reason}")]
    ParserIncompatible {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the observation.
        reason: &'static str,
    },
    /// The parser ran on the admitted source and failed.
    #[error("PARSER_FAILED: {reason}")]
    ParserFailed {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that recorded the failure.
        reason: &'static str,
    },
    /// No evaluator executed on the admitted parsed evidence.
    #[error("EVALUATOR_NOT_EXECUTED")]
    EvaluatorNotExecuted {
        /// Affected physical stream.
        stream: ProcessStreamKind,
    },
    /// The evaluator ran on the admitted parsed evidence and failed.
    #[error("EVALUATOR_FAILED: {reason}")]
    EvaluatorFailed {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that recorded the failure.
        reason: &'static str,
    },
    /// The evaluator ran but could not establish pass/fail.
    #[error("EVALUATOR_INCONCLUSIVE")]
    EvaluatorInconclusive {
        /// Affected physical stream.
        stream: ProcessStreamKind,
    },
    /// The prior evaluation no longer applies to the current fence.
    #[error("EVALUATION_STALE")]
    EvaluationStale {
        /// Affected physical stream.
        stream: ProcessStreamKind,
    },
    /// The evaluation names an artifact binding that disagrees with the
    /// admitted exact binding.
    #[error("ARTIFACT_BINDING_MISMATCH: {reason}")]
    ArtifactBindingMismatch {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the observation.
        reason: &'static str,
    },
    /// The stream carries only a legacy reference, which can never satisfy
    /// current verification.
    #[error("LEGACY_STREAM_EVIDENCE_UNAVAILABLE: {reason}")]
    LegacyStreamEvidenceUnavailable {
        /// Affected physical stream.
        stream: ProcessStreamKind,
        /// Deterministic rule that refused the evidence.
        reason: &'static str,
    },
    /// The readback request itself is malformed.
    #[error("READBACK_REQUEST_INVALID: {field}: {reason}")]
    ReadbackRequestInvalid {
        /// Request field that failed validation.
        field: &'static str,
        /// Deterministic rule that refused the request.
        reason: &'static str,
    },
}

impl TestdEvidenceError {
    /// Returns the stable machine-readable code of this error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BindingMismatch { .. } => "PROCESS_EVIDENCE_BINDING_MISMATCH",
            Self::DenominatorIncomplete { .. } => "STREAM_DENOMINATOR_INCOMPLETE",
            Self::SourceUnavailable { .. } => "STREAM_SOURCE_UNAVAILABLE",
            Self::SourcePartial { .. } => "STREAM_SOURCE_PARTIAL",
            Self::SourcePolicyProhibited { .. } => "STREAM_SOURCE_POLICY_PROHIBITED",
            Self::SourceRedactionFailed { .. } => "STREAM_SOURCE_REDACTION_FAILED",
            Self::SourcePurged { .. } => "STREAM_SOURCE_PURGED",
            Self::SourceRetentionBlocked { .. } => "STREAM_SOURCE_RETENTION_BLOCKED",
            Self::SourceIntegrityBroken { .. } => "STREAM_SOURCE_INTEGRITY_BROKEN",
            Self::SourceStale { .. } => "STREAM_SOURCE_STALE",
            Self::SourceUnknownOutcome { .. } => "STREAM_SOURCE_UNKNOWN_OUTCOME",
            Self::ReadbackIdentityMismatch { .. } => "STREAM_READBACK_IDENTITY_MISMATCH",
            Self::ReadbackDigestMismatch { .. } => "STREAM_READBACK_DIGEST_MISMATCH",
            Self::ReadbackLengthMismatch { .. } => "STREAM_READBACK_LENGTH_MISMATCH",
            Self::ParserNotExecuted { .. } => "PARSER_NOT_EXECUTED",
            Self::ParserIncompatible { .. } => "PARSER_INCOMPATIBLE",
            Self::ParserFailed { .. } => "PARSER_FAILED",
            Self::EvaluatorNotExecuted { .. } => "EVALUATOR_NOT_EXECUTED",
            Self::EvaluatorFailed { .. } => "EVALUATOR_FAILED",
            Self::EvaluatorInconclusive { .. } => "EVALUATOR_INCONCLUSIVE",
            Self::EvaluationStale { .. } => "EVALUATION_STALE",
            Self::ArtifactBindingMismatch { .. } => "ARTIFACT_BINDING_MISMATCH",
            Self::LegacyStreamEvidenceUnavailable { .. } => "LEGACY_STREAM_EVIDENCE_UNAVAILABLE",
            Self::ReadbackRequestInvalid { .. } => "READBACK_REQUEST_INVALID",
        }
    }
}

impl From<TestdEvidenceError> for TestdError {
    fn from(error: TestdEvidenceError) -> Self {
        Self::Contract(error.to_string())
    }
}

/// Closed per-stream source disposition.
///
/// Partial, unavailable, policy-prohibited, redaction-failed, purged,
/// retention-blocked, corrupt, stale, unknown, legacy, and never-emitted
/// streams remain distinct values; no path collapses two of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestdStreamDisposition {
    /// Admitted with a durable source; readback through the injected port is
    /// still required before parsing, evaluation, or citation.
    ReadbackPending,
    /// Complete source: complete transport, complete persistence, immutable
    /// locator, ready receipt, no gaps, and exact readback digest/length.
    CompleteSource,
    /// Some exact representation is durable, but full stream coverage is not
    /// proven. Explicit gaps are retained on the binding.
    PartialSource,
    /// No durable expansion source is available.
    SourceUnavailable,
    /// The requested stream is absent from the emitted record. This is an
    /// explicit denominator gap, never a silent omission.
    StreamNotEmitted,
    /// Policy forbids retention or disclosure of the source bytes. No readback
    /// is attempted and no raw bytes are exposed.
    PolicyProhibited,
    /// Required redaction/transformation failed. No readback is attempted and
    /// no raw bytes are exposed.
    RedactionFailed,
    /// The admitted source was purged before readback completed.
    Purged,
    /// Retention policy blocks readback of the admitted source.
    RetentionBlocked,
    /// Readback bytes disagree with the admitted source identity.
    IntegrityBroken,
    /// The source or its fence no longer applies to the current attempt.
    Stale,
    /// The source outcome itself cannot be established.
    UnknownOutcome,
    /// The stream carries only a legacy reference. Retained as provenance;
    /// it can never be expanded and can never satisfy verification, even if
    /// caller-supplied bytes with a matching digest arrive later.
    LegacyMigrationRequired,
}

/// Closed terminal evidence disposition for one admitted record.
///
/// A verifier result may be cited only under [`CompleteEvidence`](Self::CompleteEvidence);
/// every other value is a typed partial/inconclusive/failed/unavailable
/// outcome. This disposition never decides task finish.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestdEvidenceDisposition {
    /// Every requested stream resolved to a complete source.
    CompleteEvidence,
    /// At least one stream is partial while none failed and the denominator
    /// is otherwise covered.
    PartialEvidence,
    /// Evidence is complete but evaluation could not establish pass/fail.
    InconclusiveEvidence,
    /// Evidence handling failed: integrity break, policy prohibition,
    /// redaction failure, or parser failure.
    FailedEvidence,
    /// A requested stream is missing, unavailable, purged, stale, unknown, or
    /// legacy-only, or readback is still pending.
    #[default]
    UnavailableEvidence,
}

/// Closed parsing axis for one stream binding.
///
/// Parsing remains independent from capture and persistence: admitting a
/// stream or resolving its source never changes this status.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestdParsingStatus {
    /// No parser executed on the admitted source.
    #[default]
    NotExecuted,
    /// A parser accepted the declared source under its exact contract.
    Parsed,
    /// A parser ran on the declared source and failed. Distinct from
    /// evaluator failure.
    ParseFailed,
    /// Parsing does not apply to the declared evidence use.
    NotApplicable,
    /// Parsing was refused because no complete or supported-partial source
    /// was available.
    SourceUnavailable,
}

/// Closed evaluation axis for one stream binding.
///
/// Evaluation remains independent from execution, capture, persistence, and
/// parsing. Parser success never sets evaluator `PASS`, and evaluator `PASS`
/// never implies task finish.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestdEvaluationStatus {
    /// No Evaluation Contract has assessed the admitted parsed evidence.
    #[default]
    Unassessed,
    /// A downstream evaluator passed the declared property on applicable
    /// parsed evidence with an exact artifact binding under the current fence.
    Pass,
    /// A downstream evaluator failed the declared property. Distinct from
    /// parser failure.
    Fail,
    /// Evaluation ran but could not establish pass/fail.
    Inconclusive,
    /// The prior evaluation no longer applies to the current fence or source.
    Stale,
}

/// Exact artifact binding for one stream binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestdArtifactBinding {
    /// No artifact is bound yet.
    Unbound,
    /// The exact artifact the parser/evaluator consumed.
    BoundExact(String),
    /// Only part of the expected artifact is bound; a `PASS` recorded under
    /// this binding is non-verifying.
    BoundPartial(String),
}

/// Parser identity/revision and parsing status for one stream binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdParserSlot {
    /// Parser identity that executed, when one did.
    #[serde(default)]
    pub parser_id: Option<String>,
    /// Exact parser revision/contract that executed, when one did.
    #[serde(default)]
    pub parser_revision: Option<String>,
    /// Closed parsing status.
    pub status: TestdParsingStatus,
}

impl TestdParserSlot {
    /// Returns the not-executed slot every admission starts from.
    #[must_use]
    pub const fn not_executed() -> Self {
        Self {
            parser_id: None,
            parser_revision: None,
            status: TestdParsingStatus::NotExecuted,
        }
    }

    /// Revalidates slot coherence: an executed parser always names its exact
    /// identity and revision, and an idle slot names neither.
    pub fn validate(&self) -> Result<(), TestdEvidenceError> {
        match self.status {
            TestdParsingStatus::NotExecuted | TestdParsingStatus::SourceUnavailable => {
                if self.parser_id.is_some() || self.parser_revision.is_some() {
                    return Err(TestdEvidenceError::BindingMismatch {
                        reason: "an idle parser slot cannot name a parser identity",
                    });
                }
            }
            TestdParsingStatus::Parsed
            | TestdParsingStatus::ParseFailed
            | TestdParsingStatus::NotApplicable => {
                validate_reference("parser_id", self.parser_id.as_deref())?;
                validate_reference("parser_revision", self.parser_revision.as_deref())?;
            }
        }
        Ok(())
    }
}

/// Evaluator identity/revision, evaluation status, and applicability for one
/// stream binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdEvaluatorSlot {
    /// Evaluator identity that executed, when one did.
    #[serde(default)]
    pub evaluator_id: Option<String>,
    /// Exact evaluator revision/contract that executed, when one did.
    #[serde(default)]
    pub evaluator_revision: Option<String>,
    /// Closed evaluation status.
    pub status: TestdEvaluationStatus,
    /// Declared property the evaluator assessed, when one executed.
    #[serde(default)]
    pub property: Option<String>,
}

impl TestdEvaluatorSlot {
    /// Returns the unassessed slot every admission starts from.
    #[must_use]
    pub const fn unassessed() -> Self {
        Self {
            evaluator_id: None,
            evaluator_revision: None,
            status: TestdEvaluationStatus::Unassessed,
            property: None,
        }
    }

    /// Revalidates slot coherence: an executed evaluator always names its
    /// exact identity, revision, and assessed property.
    pub fn validate(&self) -> Result<(), TestdEvidenceError> {
        match self.status {
            TestdEvaluationStatus::Unassessed | TestdEvaluationStatus::Stale => {
                if self.evaluator_id.is_some()
                    || self.evaluator_revision.is_some()
                    || self.property.is_some()
                {
                    return Err(TestdEvidenceError::BindingMismatch {
                        reason: "an idle evaluator slot cannot name an evaluator identity",
                    });
                }
            }
            TestdEvaluationStatus::Pass
            | TestdEvaluationStatus::Fail
            | TestdEvaluationStatus::Inconclusive => {
                validate_reference("evaluator_id", self.evaluator_id.as_deref())?;
                validate_reference("evaluator_revision", self.evaluator_revision.as_deref())?;
                validate_reference("evaluator_property", self.property.as_deref())?;
            }
        }
        Ok(())
    }
}

/// Attempt context the composition supplies for one readback resolution.
///
/// The job/attempt/invocation identities and the current [`StateFence`] come
/// from the durable attempt owner, never from the evidence bytes.
#[derive(Clone, Debug)]
pub struct TestdReadbackContext {
    /// Durable job identity the resolution serves.
    pub job_id: String,
    /// Instrument invocation identity the resolution serves.
    pub invocation_id: String,
    /// Current State Fence the readback must satisfy.
    pub fence: StateFence,
    /// Maximum source bytes the caller accepts. Must cover the admitted
    /// source length; anything larger fails closed.
    pub max_bytes: u64,
    /// Unix-millisecond deadline the provider must meet.
    pub deadline_ms: u64,
}

/// Provider-neutral immutable-source readback request.
///
/// Every field needed to resolve and verify the exact source is carried
/// here; the port grants no parsing, evaluation, or finish authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSourceReadbackRequest {
    /// Durable job identity the readback serves.
    pub job_id: String,
    /// Instrument invocation identity the readback serves.
    pub invocation_id: String,
    /// Exact process/authority binding of the admitted stream.
    pub binding: ProcessExecutionBinding,
    /// Stdout or stderr.
    pub stream: ProcessStreamKind,
    /// Immutable locator class.
    pub locator_kind: DurableStreamLocatorKind,
    /// Immutable source locator value.
    pub locator: String,
    /// Ready-receipt identity proving the locator is durably ready.
    pub ready_receipt_ref: String,
    /// Expected SHA-256 over the exact durable source bytes.
    pub expected_sha256: String,
    /// Expected exact durable source length.
    pub expected_byte_length: u64,
    /// Policy/privacy/visibility/retention binding fixed before persistence.
    pub policy: ProcessStreamPolicyBinding,
    /// State Fence the readback must satisfy.
    pub fence: StateFence,
    /// Maximum source bytes the caller accepts.
    pub max_bytes: u64,
    /// Unix-millisecond deadline the provider must meet.
    pub deadline_ms: u64,
}

impl ProcessStreamSourceReadbackRequest {
    /// Validates request shape before any provider call.
    pub fn validate(&self) -> Result<(), TestdEvidenceError> {
        validate_reference("job_id", Some(self.job_id.as_str())).map_err(|_| {
            TestdEvidenceError::ReadbackRequestInvalid {
                field: "job_id",
                reason: "job identity must be non-blank and control-free",
            }
        })?;
        validate_reference("invocation_id", Some(self.invocation_id.as_str())).map_err(|_| {
            TestdEvidenceError::ReadbackRequestInvalid {
                field: "invocation_id",
                reason: "invocation identity must be non-blank and control-free",
            }
        })?;
        validate_reference("locator", Some(self.locator.as_str())).map_err(|_| {
            TestdEvidenceError::ReadbackRequestInvalid {
                field: "locator",
                reason: "source locator must be non-blank and control-free",
            }
        })?;
        validate_reference("ready_receipt_ref", Some(self.ready_receipt_ref.as_str())).map_err(
            |_| TestdEvidenceError::ReadbackRequestInvalid {
                field: "ready_receipt_ref",
                reason: "ready-receipt identity must be non-blank and control-free",
            },
        )?;
        validate_digest("expected_sha256", self.expected_sha256.as_str()).map_err(|_| {
            TestdEvidenceError::ReadbackRequestInvalid {
                field: "expected_sha256",
                reason: "expected source digest must be a lowercase SHA-256",
            }
        })?;
        if self.max_bytes < self.expected_byte_length {
            return Err(TestdEvidenceError::ReadbackRequestInvalid {
                field: "max_bytes",
                reason: "the byte bound must cover the admitted source length",
            });
        }
        if self.deadline_ms == 0 {
            return Err(TestdEvidenceError::ReadbackRequestInvalid {
                field: "deadline_ms",
                reason: "the provider deadline must be non-zero",
            });
        }
        self.fence
            .validate()
            .map_err(|_| TestdEvidenceError::ReadbackRequestInvalid {
                field: "fence",
                reason: "the readback fence must carry a non-zero resource generation",
            })?;
        Ok(())
    }
}

/// Owner-issued immutable-source readback observation.
///
/// The byte buffer is ephemeral parser input: it is skipped by serialization
/// so it can never be embedded in a durable job or receipt. Only the
/// locator/receipt/digest/length bindings below persist.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSourceReadbackObservation {
    /// Exact source bytes. Ephemeral: never serialized, never persisted.
    #[serde(skip)]
    bytes: Vec<u8>,
    /// Digest observed by the provider over the returned bytes.
    pub observed_sha256: String,
    /// Length observed by the provider over the returned bytes.
    pub observed_byte_length: u64,
    /// Locator class the provider resolved.
    pub locator_kind: DurableStreamLocatorKind,
    /// Locator value the provider resolved.
    pub locator: String,
    /// Ready-receipt identity the provider resolved.
    pub ready_receipt_ref: String,
    /// Source-owner generation that served the readback.
    pub source_owner_generation: u64,
    /// Owner-issued readback operation/receipt identity.
    pub readback_receipt_id: String,
    /// State Fence observed by the provider at readback time.
    pub observed_fence: StateFence,
    /// Clock observed by the provider at readback time.
    pub observed_at: ClockReading,
    /// Availability/integrity outcome of the readback.
    pub disposition: TestdStreamDisposition,
}

impl std::fmt::Debug for ProcessStreamSourceReadbackObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessStreamSourceReadbackObservation")
            .field("bytes_len", &self.bytes.len())
            .field("observed_sha256", &self.observed_sha256)
            .field("observed_byte_length", &self.observed_byte_length)
            .field("locator_kind", &self.locator_kind)
            .field("locator", &self.locator)
            .field("ready_receipt_ref", &self.ready_receipt_ref)
            .field("source_owner_generation", &self.source_owner_generation)
            .field("readback_receipt_id", &self.readback_receipt_id)
            .field("observed_fence", &self.observed_fence)
            .field("observed_at", &self.observed_at)
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl ProcessStreamSourceReadbackObservation {
    /// Builds one observation around provider-returned bytes.
    #[allow(
        clippy::too_many_arguments,
        reason = "readback observation carries the closed locator/receipt/digest/fence binding; a builder would hide required fields"
    )]
    pub fn new(
        bytes: Vec<u8>,
        observed_sha256: impl Into<String>,
        observed_byte_length: u64,
        locator_kind: DurableStreamLocatorKind,
        locator: impl Into<String>,
        ready_receipt_ref: impl Into<String>,
        source_owner_generation: u64,
        readback_receipt_id: impl Into<String>,
        observed_fence: StateFence,
        observed_at: ClockReading,
        disposition: TestdStreamDisposition,
    ) -> Self {
        Self {
            bytes,
            observed_sha256: observed_sha256.into(),
            observed_byte_length,
            locator_kind,
            locator: locator.into(),
            ready_receipt_ref: ready_receipt_ref.into(),
            source_owner_generation,
            readback_receipt_id: readback_receipt_id.into(),
            observed_fence,
            observed_at,
            disposition,
        }
    }

    /// Borrows the ephemeral source bytes for immediate parser input.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Verifies this observation against the admitted request, fail-closed.
    ///
    /// Testd never trusts the provider's claimed digest: the core recomputes
    /// SHA-256 over the returned bytes and requires locator, ready receipt,
    /// digest, length, byte bound, and fence to all match the admitted
    /// source. A zero-byte complete source verifies exactly like any other
    /// length: empty bytes with the empty digest and length zero.
    pub fn verify_against(
        &self,
        request: &ProcessStreamSourceReadbackRequest,
    ) -> Result<(), TestdEvidenceError> {
        let stream = request.stream;
        match self.disposition {
            TestdStreamDisposition::CompleteSource | TestdStreamDisposition::PartialSource => {}
            TestdStreamDisposition::Purged => {
                return Err(TestdEvidenceError::SourcePurged {
                    stream,
                    reason: "the provider reports the admitted source purged",
                });
            }
            TestdStreamDisposition::RetentionBlocked => {
                return Err(TestdEvidenceError::SourceRetentionBlocked {
                    stream,
                    reason: "retention policy blocks readback of the admitted source",
                });
            }
            TestdStreamDisposition::Stale => {
                return Err(TestdEvidenceError::SourceStale {
                    stream,
                    reason: "the provider reports the admitted source stale",
                });
            }
            TestdStreamDisposition::UnknownOutcome => {
                return Err(TestdEvidenceError::SourceUnknownOutcome {
                    stream,
                    reason: "the provider cannot establish the source outcome",
                });
            }
            TestdStreamDisposition::PolicyProhibited => {
                return Err(TestdEvidenceError::SourcePolicyProhibited {
                    stream,
                    reason: "policy forbids disclosure of the admitted source",
                });
            }
            TestdStreamDisposition::RedactionFailed => {
                return Err(TestdEvidenceError::SourceRedactionFailed {
                    stream,
                    reason: "redaction failed for the admitted source",
                });
            }
            TestdStreamDisposition::IntegrityBroken => {
                return Err(TestdEvidenceError::SourceIntegrityBroken {
                    stream,
                    reason: "the provider reports the admitted source corrupt",
                });
            }
            TestdStreamDisposition::SourceUnavailable => {
                return Err(TestdEvidenceError::SourceUnavailable {
                    stream,
                    reason: "the provider reports no durable source for the stream",
                });
            }
            TestdStreamDisposition::ReadbackPending
            | TestdStreamDisposition::StreamNotEmitted
            | TestdStreamDisposition::LegacyMigrationRequired => {
                return Err(TestdEvidenceError::SourceIntegrityBroken {
                    stream,
                    reason: "the provider returned a non-terminal readback disposition",
                });
            }
        }
        if self.bytes.len() as u64 > request.max_bytes {
            return Err(TestdEvidenceError::SourceIntegrityBroken {
                stream,
                reason: "the provider returned more bytes than the admitted bound",
            });
        }
        if self.locator_kind != request.locator_kind
            || self.locator != request.locator
            || self.ready_receipt_ref != request.ready_receipt_ref
        {
            return Err(TestdEvidenceError::ReadbackIdentityMismatch {
                stream,
                reason: "the readback names a different locator or ready receipt",
            });
        }
        if !self.observed_fence.is_compatible_with(&request.fence) {
            return Err(TestdEvidenceError::SourceStale {
                stream,
                reason: "the readback fence is incompatible with the attempt fence",
            });
        }
        validate_reference(
            "readback_receipt_id",
            Some(self.readback_receipt_id.as_str()),
        )
        .map_err(|_| TestdEvidenceError::ReadbackIdentityMismatch {
            stream,
            reason: "the readback receipt identity is blank or malformed",
        })?;
        let actual_bytes = self.bytes.len() as u64;
        if actual_bytes != request.expected_byte_length
            || self.observed_byte_length != request.expected_byte_length
        {
            return Err(TestdEvidenceError::ReadbackLengthMismatch {
                stream,
                reason: "the readback length disagrees with the admitted source length",
            });
        }
        let actual_sha256 = sha256_hex(&self.bytes);
        if actual_sha256 != request.expected_sha256
            || self.observed_sha256 != request.expected_sha256
        {
            return Err(TestdEvidenceError::ReadbackDigestMismatch {
                stream,
                reason: "the readback digest disagrees with the admitted source digest",
            });
        }
        Ok(())
    }
}

/// Provider-neutral immutable-source readback port.
///
/// The composition injects the owner implementation (Blob-backed once #267
/// lands); the core resolves exact bytes plus the owner-issued observation
/// through this narrow port only. The port is synchronous because the core
/// owns no runtime: composition adapts async providers at the boundary.
pub trait ProcessStreamSourceReadbackPort: Send + Sync {
    /// Resolves one admitted immutable source to exact bytes plus the
    /// owner-issued readback observation.
    ///
    /// The returned bytes are ephemeral parser input. Returning bytes for a
    /// policy-prohibited or redaction-failed source is a provider contract
    /// violation: the core checks gaps before calling and re-verifies every
    /// binding after the call.
    fn resolve(
        &self,
        request: &ProcessStreamSourceReadbackRequest,
    ) -> Result<ProcessStreamSourceReadbackObservation, TestdEvidenceError>;
}

/// Ephemeral resolved source bytes for immediate parser input.
///
/// Deliberately not serializable, so resolved bytes cannot be embedded in a
/// durable job or receipt by construction. The [`Debug`] projection reports
/// only the length, never the bytes.
pub struct EphemeralSourceBytes(Vec<u8>);

impl std::fmt::Debug for EphemeralSourceBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EphemeralSourceBytes")
            .field("len", &self.0.len())
            .finish()
    }
}

impl EphemeralSourceBytes {
    /// Borrows the resolved bytes for immediate parser input.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the resolved byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the resolved source is zero-byte.
    ///
    /// A zero-byte complete source is valid raw evidence and is distinct
    /// from a missing or unavailable source.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Owner-neutral typed stream record preserving the complete admitted source
/// description.
///
/// The record keeps the exact [`ProcessExecutionBinding`] and
/// [`ProcessStreamKind`], the complete [`ProcessStreamEvidence`] revision and
/// content identity, the immutable source locator kind/value, ready-receipt
/// identity, source digest and byte length, the source representation and
/// transformation/policy binding, transport and persistence states plus gaps,
/// parser identity/revision and parsing status, evaluator identity/revision,
/// evaluation status and applicability, the exact artifact binding and State
/// Fence, the readback receipt identity, and the explicit legacy/unavailable
/// disposition.
///
/// The record never carries preview bytes or caller-supplied bytes: source
/// bytes arrive only through [`TestdStreamEvidenceBinding::resolve_source`]
/// and leave only as [`EphemeralSourceBytes`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdStreamEvidenceBinding {
    /// [`ProcessStreamEvidence`] wire revision the record was admitted from.
    pub evidence_revision: String,
    /// Content identity over the complete admitted typed evidence value.
    pub evidence_identity_sha256: String,
    /// Exact process/authority binding, equal to the enclosing record.
    pub binding: ProcessExecutionBinding,
    /// Stdout or stderr, matching the record slot position.
    pub stream: ProcessStreamKind,
    /// Immutable locator class, when a durable source was admitted.
    #[serde(default)]
    pub locator_kind: Option<DurableStreamLocatorKind>,
    /// Immutable source locator value, when a durable source was admitted.
    #[serde(default)]
    pub locator: Option<String>,
    /// Ready-receipt identity, when a durable source was admitted.
    #[serde(default)]
    pub ready_receipt_ref: Option<String>,
    /// SHA-256 over the exact durable source bytes, when admitted.
    #[serde(default)]
    pub source_sha256: Option<String>,
    /// Exact durable source length, when admitted. Zero is valid.
    #[serde(default)]
    pub source_byte_length: Option<u64>,
    /// Relationship between durable bytes and transport bytes, when admitted.
    #[serde(default)]
    pub representation: Option<DurableStreamRepresentation>,
    /// Transformation binding for a policy-transformed source, when admitted.
    #[serde(default)]
    pub transformation: Option<ProcessStreamTransformationBinding>,
    /// Policy/privacy/visibility/retention binding fixed before persistence.
    pub policy: ProcessStreamPolicyBinding,
    /// Physical capture completion.
    pub transport: StreamTransportStatus,
    /// Exact source durability.
    pub persistence: StreamPersistenceStatus,
    /// SHA-256 over every physical transport byte observed.
    pub observed_sha256: String,
    /// Number of physical transport bytes observed.
    pub observed_bytes: u64,
    /// Explicit coverage gaps, in canonical provider order.
    pub gaps: Vec<StreamEvidenceGap>,
    /// Parser identity/revision and parsing status.
    pub parser: TestdParserSlot,
    /// Evaluator identity/revision, evaluation status, and applicability.
    pub evaluator: TestdEvaluatorSlot,
    /// Exact artifact binding.
    pub artifact_binding: TestdArtifactBinding,
    /// State Fence bound at successful readback, when resolved.
    #[serde(default)]
    pub fence: Option<StateFence>,
    /// Owner-issued readback receipt identity, when resolved.
    #[serde(default)]
    pub readback_receipt_id: Option<String>,
    /// Clock the provider observed at readback time, when resolved.
    #[serde(default)]
    pub readback_observed_at: Option<ClockReading>,
    /// Legacy reference retained as provenance only, when the stream carries
    /// one. It can never be expanded and never satisfies verification.
    #[serde(default)]
    pub legacy_reference: Option<String>,
    /// Explicit per-stream source disposition.
    pub disposition: TestdStreamDisposition,
}

impl TestdStreamEvidenceBinding {
    /// Admits one typed stream value into an owner-neutral record.
    ///
    /// `record_binding` is the enclosing [`ProcessEvidence`] binding: the
    /// stream binding must equal it, and `expected_stream` must equal the
    /// stream's own kind (kind uniqueness and slot-position match). The
    /// admission never queries legacy references for current evidence: a
    /// stream carrying a legacy reference is classified
    /// [`LegacyMigrationRequired`](TestdStreamDisposition::LegacyMigrationRequired)
    /// with the reference retained as provenance only.
    ///
    /// Admission sets no parser/evaluator status and performs no readback;
    /// source-bearing records land in
    /// [`ReadbackPending`](TestdStreamDisposition::ReadbackPending) (or
    /// [`PartialSource`](TestdStreamDisposition::PartialSource)) until
    /// [`resolve_source`](Self::resolve_source) verifies the exact source.
    pub fn admit(
        evidence: &ProcessStreamEvidence,
        record_binding: &ProcessExecutionBinding,
        expected_stream: ProcessStreamKind,
    ) -> Result<Self, TestdEvidenceError> {
        evidence
            .validate()
            .map_err(|_| TestdEvidenceError::BindingMismatch {
                reason: "the typed stream value failed contract validation",
            })?;
        if evidence.binding() != record_binding {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "the stream binding disagrees with its enclosing record",
            });
        }
        if evidence.stream() != expected_stream {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "the stream kind disagrees with its record slot position",
            });
        }
        let identity =
            evidence
                .identity_sha256()
                .map_err(|_| TestdEvidenceError::BindingMismatch {
                    reason: "the typed stream content identity is not computable",
                })?;
        let gaps = evidence.gaps().to_vec();
        if gaps.len() > MAX_BINDING_GAPS {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "the admitted gap list exceeds the binding bound",
            });
        }
        if evidence.legacy_reference().is_some() {
            return Ok(Self {
                evidence_revision: evidence.schema_version().to_owned(),
                evidence_identity_sha256: identity,
                binding: record_binding.clone(),
                stream: expected_stream,
                locator_kind: None,
                locator: None,
                ready_receipt_ref: None,
                source_sha256: None,
                source_byte_length: None,
                representation: None,
                transformation: None,
                policy: evidence.policy().clone(),
                transport: evidence.transport(),
                persistence: evidence.persistence(),
                observed_sha256: evidence.observed_sha256().to_owned(),
                observed_bytes: evidence.observed_bytes(),
                gaps,
                parser: TestdParserSlot::not_executed(),
                evaluator: TestdEvaluatorSlot::unassessed(),
                artifact_binding: TestdArtifactBinding::Unbound,
                fence: None,
                readback_receipt_id: None,
                readback_observed_at: None,
                legacy_reference: evidence.legacy_reference().map(str::to_owned),
                disposition: TestdStreamDisposition::LegacyMigrationRequired,
            });
        }
        let source = evidence.source();
        if gaps.contains(&StreamEvidenceGap::PolicyProhibited) {
            return Ok(Self::without_source(
                evidence,
                record_binding,
                expected_stream,
                identity,
                gaps,
                TestdStreamDisposition::PolicyProhibited,
            ));
        }
        if gaps.contains(&StreamEvidenceGap::RedactionFailed) {
            return Ok(Self::without_source(
                evidence,
                record_binding,
                expected_stream,
                identity,
                gaps,
                TestdStreamDisposition::RedactionFailed,
            ));
        }
        let Some(source) = source else {
            let disposition = match evidence.persistence() {
                StreamPersistenceStatus::SourceUnavailable => {
                    TestdStreamDisposition::SourceUnavailable
                }
                StreamPersistenceStatus::PartialSource => {
                    if gaps.is_empty() {
                        return Err(TestdEvidenceError::DenominatorIncomplete {
                            reason: "a partial source claim requires explicit gaps",
                        });
                    }
                    TestdStreamDisposition::PartialSource
                }
                StreamPersistenceStatus::CompleteSource => {
                    return Err(TestdEvidenceError::DenominatorIncomplete {
                        reason: "a complete source claim requires a durable source",
                    });
                }
            };
            return Ok(Self::without_source(
                evidence,
                record_binding,
                expected_stream,
                identity,
                gaps,
                disposition,
            ));
        };
        if evidence.persistence() == StreamPersistenceStatus::PartialSource && gaps.is_empty() {
            return Err(TestdEvidenceError::DenominatorIncomplete {
                reason: "a partial source claim requires explicit gaps",
            });
        }
        // Explicit gaps override a claimed-complete source: the record stays
        // honest about uncovered ranges instead of certifying completeness.
        let disposition = if evidence.persistence() == StreamPersistenceStatus::CompleteSource
            && evidence.transport() == StreamTransportStatus::Complete
            && gaps.is_empty()
        {
            TestdStreamDisposition::ReadbackPending
        } else {
            TestdStreamDisposition::PartialSource
        };
        Ok(Self {
            evidence_revision: evidence.schema_version().to_owned(),
            evidence_identity_sha256: identity,
            binding: record_binding.clone(),
            stream: expected_stream,
            locator_kind: Some(source.kind()),
            locator: Some(source.locator().to_owned()),
            ready_receipt_ref: Some(source.ready_receipt_ref().to_owned()),
            source_sha256: Some(source.sha256().to_owned()),
            source_byte_length: Some(source.byte_length()),
            representation: Some(source.representation()),
            transformation: source.transformation().cloned(),
            policy: evidence.policy().clone(),
            transport: evidence.transport(),
            persistence: evidence.persistence(),
            observed_sha256: evidence.observed_sha256().to_owned(),
            observed_bytes: evidence.observed_bytes(),
            gaps,
            parser: TestdParserSlot::not_executed(),
            evaluator: TestdEvaluatorSlot::unassessed(),
            artifact_binding: TestdArtifactBinding::Unbound,
            fence: None,
            readback_receipt_id: None,
            readback_observed_at: None,
            legacy_reference: None,
            disposition,
        })
    }

    /// Builds a source-less record for unavailable/prohibited/partial streams.
    fn without_source(
        evidence: &ProcessStreamEvidence,
        record_binding: &ProcessExecutionBinding,
        expected_stream: ProcessStreamKind,
        identity: String,
        gaps: Vec<StreamEvidenceGap>,
        disposition: TestdStreamDisposition,
    ) -> Self {
        Self {
            evidence_revision: evidence.schema_version().to_owned(),
            evidence_identity_sha256: identity,
            binding: record_binding.clone(),
            stream: expected_stream,
            locator_kind: None,
            locator: None,
            ready_receipt_ref: None,
            source_sha256: None,
            source_byte_length: None,
            representation: None,
            transformation: None,
            policy: evidence.policy().clone(),
            transport: evidence.transport(),
            persistence: evidence.persistence(),
            observed_sha256: evidence.observed_sha256().to_owned(),
            observed_bytes: evidence.observed_bytes(),
            gaps,
            parser: TestdParserSlot::not_executed(),
            evaluator: TestdEvaluatorSlot::unassessed(),
            artifact_binding: TestdArtifactBinding::Unbound,
            fence: None,
            readback_receipt_id: None,
            readback_observed_at: None,
            legacy_reference: None,
            disposition,
        }
    }

    /// Revalidates record coherence without resolving any source.
    ///
    /// Used by receipt validation and restart reconstruction: every invariant
    /// admission established (binding equality, kind match, source-field
    /// presence per disposition, gap coherence, slot coherence, readback
    /// binding presence per disposition) is rechecked.
    pub fn validate(&self) -> Result<(), TestdEvidenceError> {
        validate_reference("evidence_revision", Some(self.evidence_revision.as_str()))?;
        validate_digest(
            "evidence_identity_sha256",
            self.evidence_identity_sha256.as_str(),
        )?;
        if self.gaps.len() > MAX_BINDING_GAPS {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "the retained gap list exceeds the binding bound",
            });
        }
        let source_fields = [
            self.locator_kind.is_some(),
            self.locator.is_some(),
            self.ready_receipt_ref.is_some(),
            self.source_sha256.is_some(),
            self.source_byte_length.is_some(),
            self.representation.is_some(),
        ];
        let has_source = source_fields.iter().all(|present| *present);
        let no_source = source_fields.iter().all(|present| !present);
        if !has_source && !no_source {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "durable source fields must be jointly present or absent",
            });
        }
        match self.disposition {
            TestdStreamDisposition::ReadbackPending
            | TestdStreamDisposition::CompleteSource
            | TestdStreamDisposition::PartialSource
            | TestdStreamDisposition::Purged
            | TestdStreamDisposition::RetentionBlocked
            | TestdStreamDisposition::IntegrityBroken
            | TestdStreamDisposition::Stale
            | TestdStreamDisposition::UnknownOutcome => {
                if !has_source {
                    return Err(TestdEvidenceError::BindingMismatch {
                        reason: "a source-bearing disposition requires the durable source fields",
                    });
                }
            }
            TestdStreamDisposition::SourceUnavailable
            | TestdStreamDisposition::StreamNotEmitted
            | TestdStreamDisposition::PolicyProhibited
            | TestdStreamDisposition::RedactionFailed
            | TestdStreamDisposition::LegacyMigrationRequired => {
                if !no_source {
                    return Err(TestdEvidenceError::BindingMismatch {
                        reason: "a source-less disposition cannot carry durable source fields",
                    });
                }
            }
        }
        if has_source {
            let locator = self.locator.as_deref().unwrap_or_default();
            validate_reference("locator", Some(locator))?;
            validate_reference("ready_receipt_ref", self.ready_receipt_ref.as_deref())?;
            validate_digest(
                "source_sha256",
                self.source_sha256.as_deref().unwrap_or_default(),
            )?;
        }
        if self.disposition == TestdStreamDisposition::CompleteSource {
            if !self.gaps.is_empty() {
                return Err(TestdEvidenceError::BindingMismatch {
                    reason: "a complete source cannot retain coverage gaps",
                });
            }
            if self.transport != StreamTransportStatus::Complete
                || self.persistence != StreamPersistenceStatus::CompleteSource
            {
                return Err(TestdEvidenceError::BindingMismatch {
                    reason: "a complete source requires complete transport and persistence",
                });
            }
            if self.readback_receipt_id.is_none() || self.fence.is_none() {
                return Err(TestdEvidenceError::BindingMismatch {
                    reason: "a complete source requires a verified readback binding",
                });
            }
        }
        if self.disposition == TestdStreamDisposition::LegacyMigrationRequired {
            validate_reference("legacy_reference", self.legacy_reference.as_deref())?;
        } else if self.legacy_reference.is_some() {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "only a legacy disposition may retain a legacy reference",
            });
        }
        if self.disposition == TestdStreamDisposition::StreamNotEmitted {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "a never-emitted stream has no binding record",
            });
        }
        self.parser.validate()?;
        self.evaluator.validate()?;
        match &self.artifact_binding {
            TestdArtifactBinding::Unbound => {}
            TestdArtifactBinding::BoundExact(artifact)
            | TestdArtifactBinding::BoundPartial(artifact) => {
                validate_reference("artifact_binding", Some(artifact.as_str()))?;
            }
        }
        Ok(())
    }

    /// Returns whether this record still requires source readback.
    #[must_use]
    pub const fn needs_readback(&self) -> bool {
        matches!(
            self.disposition,
            TestdStreamDisposition::ReadbackPending | TestdStreamDisposition::PartialSource
        )
    }

    /// Resolves the admitted immutable source through the injected port.
    ///
    /// Privacy/scope/fence checks run before any provider call: legacy,
    /// unavailable, policy-prohibited, and redaction-failed records are
    /// refused without touching the port, so no byte path exists for them.
    /// On success the record keeps the readback receipt identity, fence, and
    /// observation clock; the bytes leave only as [`EphemeralSourceBytes`].
    pub fn resolve_source(
        &mut self,
        port: &dyn ProcessStreamSourceReadbackPort,
        context: &TestdReadbackContext,
    ) -> Result<EphemeralSourceBytes, TestdEvidenceError> {
        match self.disposition {
            TestdStreamDisposition::ReadbackPending
            | TestdStreamDisposition::PartialSource
            | TestdStreamDisposition::CompleteSource
            | TestdStreamDisposition::UnknownOutcome => {}
            TestdStreamDisposition::LegacyMigrationRequired => {
                return Err(TestdEvidenceError::LegacyStreamEvidenceUnavailable {
                    stream: self.stream,
                    reason: "a legacy reference can never be expanded or satisfy verification",
                });
            }
            TestdStreamDisposition::SourceUnavailable
            | TestdStreamDisposition::StreamNotEmitted => {
                return Err(TestdEvidenceError::SourceUnavailable {
                    stream: self.stream,
                    reason: "no durable source is admitted for this stream",
                });
            }
            TestdStreamDisposition::PolicyProhibited => {
                return Err(TestdEvidenceError::SourcePolicyProhibited {
                    stream: self.stream,
                    reason: "policy forbids readback before any provider call",
                });
            }
            TestdStreamDisposition::RedactionFailed => {
                return Err(TestdEvidenceError::SourceRedactionFailed {
                    stream: self.stream,
                    reason: "redaction failed before any provider call",
                });
            }
            TestdStreamDisposition::Purged => {
                return Err(TestdEvidenceError::SourcePurged {
                    stream: self.stream,
                    reason: "the admitted source is already purged",
                });
            }
            TestdStreamDisposition::RetentionBlocked => {
                return Err(TestdEvidenceError::SourceRetentionBlocked {
                    stream: self.stream,
                    reason: "retention still blocks readback of the admitted source",
                });
            }
            TestdStreamDisposition::IntegrityBroken => {
                return Err(TestdEvidenceError::SourceIntegrityBroken {
                    stream: self.stream,
                    reason: "the admitted source already failed integrity verification",
                });
            }
            TestdStreamDisposition::Stale => {
                return Err(TestdEvidenceError::SourceStale {
                    stream: self.stream,
                    reason: "the admitted source is already stale",
                });
            }
        }
        let request = self.readback_request(context)?;
        request.validate()?;
        let observation = port.resolve(&request)?;
        if let Err(error) = observation.verify_against(&request) {
            self.disposition = disposition_for_readback_error(&error);
            return Err(error);
        }
        self.fence = Some(context.fence.clone());
        self.readback_receipt_id = Some(observation.readback_receipt_id.clone());
        self.readback_observed_at = Some(observation.observed_at);
        self.disposition = if self.transport == StreamTransportStatus::Complete
            && self.persistence == StreamPersistenceStatus::CompleteSource
            && self.gaps.is_empty()
        {
            TestdStreamDisposition::CompleteSource
        } else {
            TestdStreamDisposition::PartialSource
        };
        Ok(EphemeralSourceBytes(observation.bytes.clone()))
    }

    /// Builds the readback request from the admitted source fields.
    fn readback_request(
        &self,
        context: &TestdReadbackContext,
    ) -> Result<ProcessStreamSourceReadbackRequest, TestdEvidenceError> {
        let stream = self.stream;
        let (
            Some(locator_kind),
            Some(locator),
            Some(ready_receipt_ref),
            Some(expected_sha256),
            Some(expected_byte_length),
        ) = (
            self.locator_kind,
            self.locator.clone(),
            self.ready_receipt_ref.clone(),
            self.source_sha256.clone(),
            self.source_byte_length,
        )
        else {
            return Err(TestdEvidenceError::SourceUnavailable {
                stream,
                reason: "the admitted record carries no durable source fields",
            });
        };
        Ok(ProcessStreamSourceReadbackRequest {
            job_id: context.job_id.clone(),
            invocation_id: context.invocation_id.clone(),
            binding: self.binding.clone(),
            stream,
            locator_kind,
            locator,
            ready_receipt_ref,
            expected_sha256,
            expected_byte_length,
            policy: self.policy.clone(),
            fence: context.fence.clone(),
            max_bytes: context.max_bytes,
            deadline_ms: context.deadline_ms,
        })
    }

    /// Applies one parsing observation to this record.
    ///
    /// Parsing requires a complete source, or an explicitly supported partial
    /// source, plus the exact parser contract: the observation must name this
    /// record's evidence identity and verified readback receipt, which proves
    /// the parser consumed readback bytes rather than preview or
    /// caller-supplied bytes. A successful process exit never satisfies this
    /// gate, and applying a parse result never changes evaluator status.
    pub fn apply_parsing(
        &mut self,
        observation: &TestdParsingObservation,
    ) -> Result<(), TestdEvidenceError> {
        let stream = self.stream;
        if observation.source_evidence_identity != self.evidence_identity_sha256 {
            return Err(TestdEvidenceError::ParserIncompatible {
                stream,
                reason: "the parsing observation names a different source",
            });
        }
        if self.readback_receipt_id.as_deref()
            != Some(observation.source_readback_receipt_id.as_str())
        {
            return Err(TestdEvidenceError::ParserIncompatible {
                stream,
                reason: "the parsing observation lacks this source's verified readback",
            });
        }
        match self.disposition {
            TestdStreamDisposition::CompleteSource => {}
            TestdStreamDisposition::PartialSource if observation.allows_partial_source => {}
            _ => {
                return Err(TestdEvidenceError::ParserNotExecuted { stream });
            }
        }
        validate_reference("parser_id", Some(observation.parser_id.as_str())).map_err(|_| {
            TestdEvidenceError::ParserIncompatible {
                stream,
                reason: "the parser identity is blank or malformed",
            }
        })?;
        validate_reference(
            "parser_revision",
            Some(observation.parser_revision.as_str()),
        )
        .map_err(|_| TestdEvidenceError::ParserIncompatible {
            stream,
            reason: "the parser revision is blank or malformed",
        })?;
        self.parser = TestdParserSlot {
            parser_id: Some(observation.parser_id.clone()),
            parser_revision: Some(observation.parser_revision.clone()),
            status: observation.status,
        };
        Ok(())
    }

    /// Applies one evaluation observation to this record.
    ///
    /// Evaluation requires applicable parsed evidence, an executed evaluator,
    /// an exact artifact binding, and the current State Fence: the parser
    /// must have accepted this source under the named exact contract, the
    /// observation fence must be compatible with the readback fence, and the
    /// artifact binding is recorded exactly. Parser success alone never
    /// satisfies this gate, and recording a result never decides task finish.
    pub fn apply_evaluation(
        &mut self,
        observation: &TestdEvaluationObservation,
    ) -> Result<(), TestdEvidenceError> {
        let stream = self.stream;
        if self.parser.status != TestdParsingStatus::Parsed {
            return Err(TestdEvidenceError::EvaluatorNotExecuted { stream });
        }
        if self.parser.parser_id.as_deref() != Some(observation.parser_id.as_str())
            || self.parser.parser_revision.as_deref() != Some(observation.parser_revision.as_str())
        {
            return Err(TestdEvidenceError::EvaluatorNotExecuted { stream });
        }
        if observation.parsed_source_identity != self.evidence_identity_sha256 {
            return Err(TestdEvidenceError::ArtifactBindingMismatch {
                stream,
                reason: "the evaluation names a different parsed source",
            });
        }
        let readback_fence = self.fence.as_ref().ok_or(TestdEvidenceError::SourceStale {
            stream,
            reason: "evaluation requires a fenced readback binding",
        })?;
        if !observation.fence.is_compatible_with(readback_fence) {
            self.evaluator = TestdEvaluatorSlot::unassessed();
            return Err(TestdEvidenceError::EvaluationStale { stream });
        }
        validate_reference("artifact_id", Some(observation.artifact_id.as_str())).map_err(
            |_| TestdEvidenceError::ArtifactBindingMismatch {
                stream,
                reason: "the evaluation artifact binding is blank or malformed",
            },
        )?;
        validate_reference("evaluator_id", Some(observation.evaluator_id.as_str()))
            .map_err(|_| TestdEvidenceError::EvaluatorNotExecuted { stream })?;
        validate_reference(
            "evaluator_revision",
            Some(observation.evaluator_revision.as_str()),
        )
        .map_err(|_| TestdEvidenceError::EvaluatorNotExecuted { stream })?;
        validate_reference("evaluator_property", Some(observation.property.as_str()))
            .map_err(|_| TestdEvidenceError::EvaluatorNotExecuted { stream })?;
        self.artifact_binding = if observation.artifact_partial {
            TestdArtifactBinding::BoundPartial(observation.artifact_id.clone())
        } else {
            TestdArtifactBinding::BoundExact(observation.artifact_id.clone())
        };
        self.evaluator = TestdEvaluatorSlot {
            evaluator_id: Some(observation.evaluator_id.clone()),
            evaluator_revision: Some(observation.evaluator_revision.clone()),
            status: observation.status,
            property: Some(observation.property.clone()),
        };
        Ok(())
    }

    /// Revalidates the evaluation against the current fence.
    ///
    /// A fence advance that invalidates the readback fence marks a recorded
    /// evaluation stale; the observation is dropped rather than reinterpreted,
    /// so an evaluator `PASS` can never survive its fence.
    pub fn revalidate_fence(&mut self, current: &StateFence) {
        let compatible = self
            .fence
            .as_ref()
            .is_some_and(|fence| current.is_compatible_with(fence));
        if !compatible
            && !matches!(
                self.evaluator.status,
                TestdEvaluationStatus::Unassessed | TestdEvaluationStatus::Stale
            )
        {
            self.evaluator = TestdEvaluatorSlot {
                evaluator_id: None,
                evaluator_revision: None,
                status: TestdEvaluationStatus::Stale,
                property: None,
            };
        }
    }
}

/// Parsing observation for one resolved stream source.
///
/// The observation binds the exact parser contract to this source's evidence
/// identity and verified readback receipt; only
/// [`TestdStreamEvidenceBinding::apply_parsing`] may record it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdParsingObservation {
    /// Parser identity that executed.
    pub parser_id: String,
    /// Exact parser revision/contract that executed.
    pub parser_revision: String,
    /// Parsing outcome. Only executed outcomes are representable.
    pub status: TestdParsingStatus,
    /// Evidence identity of the source the parser consumed.
    pub source_evidence_identity: String,
    /// Verified readback receipt of the source the parser consumed.
    pub source_readback_receipt_id: String,
    /// Whether this parser contract explicitly supports partial sources.
    pub allows_partial_source: bool,
    /// Clock the parser observed at execution time.
    pub observed_at: ClockReading,
}

impl TestdParsingObservation {
    /// Builds one observation, refusing non-executed statuses.
    pub fn new(
        parser_id: impl Into<String>,
        parser_revision: impl Into<String>,
        status: TestdParsingStatus,
        source_evidence_identity: impl Into<String>,
        source_readback_receipt_id: impl Into<String>,
        allows_partial_source: bool,
        observed_at: ClockReading,
    ) -> Result<Self, TestdEvidenceError> {
        match status {
            TestdParsingStatus::Parsed
            | TestdParsingStatus::ParseFailed
            | TestdParsingStatus::NotApplicable => {}
            TestdParsingStatus::NotExecuted | TestdParsingStatus::SourceUnavailable => {
                return Err(TestdEvidenceError::ParserNotExecuted {
                    stream: ProcessStreamKind::Stdout,
                });
            }
        }
        Ok(Self {
            parser_id: parser_id.into(),
            parser_revision: parser_revision.into(),
            status,
            source_evidence_identity: source_evidence_identity.into(),
            source_readback_receipt_id: source_readback_receipt_id.into(),
            allows_partial_source,
            observed_at,
        })
    }
}

/// Evaluation observation for one parsed stream source.
///
/// The observation binds the exact evaluator contract and artifact to the
/// parsed source identity and the evaluation fence; only
/// [`TestdStreamEvidenceBinding::apply_evaluation`] may record it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdEvaluationObservation {
    /// Evaluator identity that executed.
    pub evaluator_id: String,
    /// Exact evaluator revision/contract that executed.
    pub evaluator_revision: String,
    /// Evaluation outcome. Only executed outcomes are representable.
    pub status: TestdEvaluationStatus,
    /// Declared property under assessment.
    pub property: String,
    /// Evidence identity of the parsed source the evaluator consumed.
    pub parsed_source_identity: String,
    /// Parser identity whose output the evaluator consumed.
    pub parser_id: String,
    /// Exact parser revision whose output the evaluator consumed.
    pub parser_revision: String,
    /// Exact artifact the evaluator assessed.
    pub artifact_id: String,
    /// Whether only part of the expected artifact is bound. A `PASS` with a
    /// partial binding is non-verifying.
    pub artifact_partial: bool,
    /// State Fence at evaluation time.
    pub fence: StateFence,
    /// Clock the evaluator observed at execution time.
    pub observed_at: ClockReading,
}

impl TestdEvaluationObservation {
    /// Builds one observation, refusing non-executed statuses.
    #[allow(
        clippy::too_many_arguments,
        reason = "evaluation observation carries the closed parser/artifact/fence binding; a builder would hide required fields"
    )]
    pub fn new(
        evaluator_id: impl Into<String>,
        evaluator_revision: impl Into<String>,
        status: TestdEvaluationStatus,
        property: impl Into<String>,
        parsed_source_identity: impl Into<String>,
        parser_id: impl Into<String>,
        parser_revision: impl Into<String>,
        artifact_id: impl Into<String>,
        artifact_partial: bool,
        fence: StateFence,
        observed_at: ClockReading,
    ) -> Result<Self, TestdEvidenceError> {
        match status {
            TestdEvaluationStatus::Pass
            | TestdEvaluationStatus::Fail
            | TestdEvaluationStatus::Inconclusive => {}
            TestdEvaluationStatus::Unassessed | TestdEvaluationStatus::Stale => {
                return Err(TestdEvidenceError::EvaluatorNotExecuted {
                    stream: ProcessStreamKind::Stdout,
                });
            }
        }
        Ok(Self {
            evaluator_id: evaluator_id.into(),
            evaluator_revision: evaluator_revision.into(),
            status,
            property: property.into(),
            parsed_source_identity: parsed_source_identity.into(),
            parser_id: parser_id.into(),
            parser_revision: parser_revision.into(),
            artifact_id: artifact_id.into(),
            artifact_partial,
            fence,
            observed_at,
        })
    }
}

/// One requested stream slot inside a process-evidence bundle.
///
/// Both stdout and stderr always receive an explicit slot: a stream absent
/// from the emitted record is an explicit
/// [`StreamNotEmitted`](TestdStreamDisposition::StreamNotEmitted) denominator
/// gap, never a silent omission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdStreamSlot {
    /// Stdout or stderr.
    pub stream: ProcessStreamKind,
    /// Explicit per-stream source disposition.
    pub disposition: TestdStreamDisposition,
    /// Admitted record, present for every disposition except
    /// [`StreamNotEmitted`](TestdStreamDisposition::StreamNotEmitted).
    #[serde(default)]
    pub binding: Option<TestdStreamEvidenceBinding>,
}

/// Owner-neutral bundle for one emitted [`ProcessEvidence`] record.
///
/// The bundle preserves both requested streams independently with an explicit
/// disposition each, plus the terminal evidence disposition. Admission
/// consumes only the typed [`ProcessEvidence::stdout`]/[`ProcessEvidence::stderr`]
/// values; legacy references are never queried for current evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdProcessEvidenceBundle {
    /// Exact process/authority binding shared by the record and its streams.
    pub binding: ProcessExecutionBinding,
    /// Stdout slot with its explicit disposition.
    pub stdout: TestdStreamSlot,
    /// Stderr slot with its explicit disposition.
    pub stderr: TestdStreamSlot,
    /// Terminal evidence disposition derived from both slots.
    pub disposition: TestdEvidenceDisposition,
}

impl TestdProcessEvidenceBundle {
    /// Admits one emitted record into an owner-neutral bundle.
    ///
    /// Each typed stream value is admitted with its record-slot position;
    /// each absent stream becomes an explicit never-emitted gap. Admission
    /// performs no readback and sets no parser/evaluator status.
    pub fn admit(record: &ProcessEvidence) -> Result<Self, TestdEvidenceError> {
        let binding = record.binding().clone();
        let stdout = Self::admit_slot(record.stdout(), &binding, ProcessStreamKind::Stdout)?;
        let stderr = Self::admit_slot(record.stderr(), &binding, ProcessStreamKind::Stderr)?;
        let disposition = derive_evidence_disposition(&stdout, &stderr);
        Ok(Self {
            binding,
            stdout,
            stderr,
            disposition,
        })
    }

    /// Admits one record slot, or records its explicit absence.
    fn admit_slot(
        evidence: Option<&ProcessStreamEvidence>,
        record_binding: &ProcessExecutionBinding,
        stream: ProcessStreamKind,
    ) -> Result<TestdStreamSlot, TestdEvidenceError> {
        match evidence {
            Some(evidence) => {
                let admitted = TestdStreamEvidenceBinding::admit(evidence, record_binding, stream)?;
                Ok(TestdStreamSlot {
                    stream,
                    disposition: admitted.disposition,
                    binding: Some(admitted),
                })
            }
            None => Ok(TestdStreamSlot {
                stream,
                disposition: TestdStreamDisposition::StreamNotEmitted,
                binding: None,
            }),
        }
    }

    /// Revalidates bundle coherence without resolving any source.
    pub fn validate(&self) -> Result<(), TestdEvidenceError> {
        if self.stdout.stream != ProcessStreamKind::Stdout
            || self.stderr.stream != ProcessStreamKind::Stderr
        {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "bundle slots must be stdout then stderr",
            });
        }
        for slot in [&self.stdout, &self.stderr] {
            match (&slot.binding, slot.disposition) {
                (Some(binding), disposition) => {
                    if disposition == TestdStreamDisposition::StreamNotEmitted {
                        return Err(TestdEvidenceError::BindingMismatch {
                            reason: "a never-emitted stream cannot carry a binding record",
                        });
                    }
                    if binding.stream != slot.stream {
                        return Err(TestdEvidenceError::BindingMismatch {
                            reason: "a slot binding disagrees with its slot position",
                        });
                    }
                    if binding.binding != self.binding {
                        return Err(TestdEvidenceError::BindingMismatch {
                            reason: "a slot binding disagrees with its bundle binding",
                        });
                    }
                    if binding.disposition != slot.disposition {
                        return Err(TestdEvidenceError::BindingMismatch {
                            reason: "a slot disposition disagrees with its binding record",
                        });
                    }
                    binding.validate()?;
                }
                (None, TestdStreamDisposition::StreamNotEmitted) => {}
                (None, _) => {
                    return Err(TestdEvidenceError::DenominatorIncomplete {
                        reason: "an admitted stream requires its binding record",
                    });
                }
            }
        }
        if self.disposition != derive_evidence_disposition(&self.stdout, &self.stderr) {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "the bundle disposition disagrees with its slots",
            });
        }
        Ok(())
    }

    /// Resolves every pending slot through the injected port.
    ///
    /// Each slot yields an explicit per-stream outcome; refusal and failure
    /// outcomes update the slot disposition in place and never expose bytes.
    /// Resolution never fails wholesale: every requested stream keeps its
    /// explicit disposition whether or not bytes arrived.
    pub fn resolve_pending(
        &mut self,
        port: &dyn ProcessStreamSourceReadbackPort,
        context: &TestdReadbackContext,
    ) -> Vec<TestdStreamResolution> {
        let mut outcomes = Vec::with_capacity(2);
        for slot in [&mut self.stdout, &mut self.stderr] {
            outcomes.push(resolve_slot(slot, port, context));
        }
        self.disposition = derive_evidence_disposition(&self.stdout, &self.stderr);
        outcomes
    }
}

/// Explicit per-stream outcome of one readback resolution.
#[derive(Debug)]
pub enum TestdStreamResolution {
    /// The stream resolved to ephemeral source bytes for immediate parser
    /// input. The bytes are not retained on the binding.
    Resolved {
        /// Resolved physical stream.
        stream: ProcessStreamKind,
        /// Ephemeral source bytes.
        bytes: EphemeralSourceBytes,
    },
    /// The stream was refused or failed resolution with a typed error. The
    /// slot disposition was updated in place; no bytes are exposed.
    Refused {
        /// Refused physical stream.
        stream: ProcessStreamKind,
        /// Typed refusal reason.
        error: TestdEvidenceError,
    },
}

/// Resolves one slot, updating its disposition in place.
fn resolve_slot(
    slot: &mut TestdStreamSlot,
    port: &dyn ProcessStreamSourceReadbackPort,
    context: &TestdReadbackContext,
) -> TestdStreamResolution {
    let Some(binding) = slot.binding.as_mut() else {
        return TestdStreamResolution::Refused {
            stream: slot.stream,
            error: TestdEvidenceError::SourceUnavailable {
                stream: slot.stream,
                reason: "the requested stream was never emitted",
            },
        };
    };
    // Pending, already-complete (re-expansion for restart re-parse), and
    // unknown-outcome (reconcile by the same session identity) slots resolve
    // through the port; every other disposition is refused without a call.
    if binding.needs_readback()
        || matches!(
            binding.disposition,
            TestdStreamDisposition::CompleteSource | TestdStreamDisposition::UnknownOutcome
        )
    {
        return match binding.resolve_source(port, context) {
            Ok(bytes) => {
                slot.disposition = binding.disposition;
                TestdStreamResolution::Resolved {
                    stream: slot.stream,
                    bytes,
                }
            }
            Err(error) => {
                slot.disposition = binding.disposition;
                TestdStreamResolution::Refused {
                    stream: slot.stream,
                    error,
                }
            }
        };
    }
    let error = match binding.disposition {
        TestdStreamDisposition::LegacyMigrationRequired => {
            TestdEvidenceError::LegacyStreamEvidenceUnavailable {
                stream: slot.stream,
                reason: "a legacy reference can never be expanded or satisfy verification",
            }
        }
        TestdStreamDisposition::SourceUnavailable | TestdStreamDisposition::StreamNotEmitted => {
            TestdEvidenceError::SourceUnavailable {
                stream: slot.stream,
                reason: "no durable source is admitted for this stream",
            }
        }
        TestdStreamDisposition::PolicyProhibited => TestdEvidenceError::SourcePolicyProhibited {
            stream: slot.stream,
            reason: "policy forbids readback before any provider call",
        },
        TestdStreamDisposition::RedactionFailed => TestdEvidenceError::SourceRedactionFailed {
            stream: slot.stream,
            reason: "redaction failed before any provider call",
        },
        TestdStreamDisposition::Purged => TestdEvidenceError::SourcePurged {
            stream: slot.stream,
            reason: "the admitted source is already purged",
        },
        TestdStreamDisposition::RetentionBlocked => TestdEvidenceError::SourceRetentionBlocked {
            stream: slot.stream,
            reason: "retention still blocks readback of the admitted source",
        },
        TestdStreamDisposition::IntegrityBroken => TestdEvidenceError::SourceIntegrityBroken {
            stream: slot.stream,
            reason: "the admitted source already failed integrity verification",
        },
        TestdStreamDisposition::Stale => TestdEvidenceError::SourceStale {
            stream: slot.stream,
            reason: "the admitted source is already stale",
        },
        TestdStreamDisposition::ReadbackPending
        | TestdStreamDisposition::PartialSource
        | TestdStreamDisposition::CompleteSource
        | TestdStreamDisposition::UnknownOutcome => TestdEvidenceError::SourceUnknownOutcome {
            stream: slot.stream,
            reason: "unreachable resolvable disposition",
        },
    };
    TestdStreamResolution::Refused {
        stream: slot.stream,
        error,
    }
}

/// Derives the terminal evidence disposition from both slots.
///
/// Precedence is fail-closed: any integrity break, policy prohibition,
/// redaction failure, or parser failure yields failed evidence; any missing,
/// unavailable, purged, stale, unknown, legacy-only, or still-pending stream
/// yields unavailable evidence; any partial stream yields partial evidence;
/// complete evidence with an inconclusive evaluation yields inconclusive
/// evidence; otherwise the evidence is complete. No path promotes a partial
/// or unavailable denominator into a verifier result.
fn derive_evidence_disposition(
    stdout: &TestdStreamSlot,
    stderr: &TestdStreamSlot,
) -> TestdEvidenceDisposition {
    let slots = [stdout, stderr];
    if slots.iter().any(|slot| {
        matches!(
            slot.disposition,
            TestdStreamDisposition::IntegrityBroken
                | TestdStreamDisposition::PolicyProhibited
                | TestdStreamDisposition::RedactionFailed
        ) || slot
            .binding
            .as_ref()
            .is_some_and(|binding| binding.parser.status == TestdParsingStatus::ParseFailed)
    }) {
        return TestdEvidenceDisposition::FailedEvidence;
    }
    if slots.iter().any(|slot| {
        matches!(
            slot.disposition,
            TestdStreamDisposition::ReadbackPending
                | TestdStreamDisposition::SourceUnavailable
                | TestdStreamDisposition::StreamNotEmitted
                | TestdStreamDisposition::Purged
                | TestdStreamDisposition::RetentionBlocked
                | TestdStreamDisposition::Stale
                | TestdStreamDisposition::UnknownOutcome
                | TestdStreamDisposition::LegacyMigrationRequired
        )
    }) {
        return TestdEvidenceDisposition::UnavailableEvidence;
    }
    if slots
        .iter()
        .any(|slot| slot.disposition == TestdStreamDisposition::PartialSource)
    {
        return TestdEvidenceDisposition::PartialEvidence;
    }
    if slots.iter().any(|slot| {
        slot.binding
            .as_ref()
            .is_some_and(|binding| binding.evaluator.status == TestdEvaluationStatus::Inconclusive)
    }) {
        return TestdEvidenceDisposition::InconclusiveEvidence;
    }
    TestdEvidenceDisposition::CompleteEvidence
}

/// Maps a readback failure onto the retained slot disposition.
///
/// Every error family keeps its distinct disposition; digest, length, and
/// identity mismatches all prove corruption rather than staleness.
fn disposition_for_readback_error(error: &TestdEvidenceError) -> TestdStreamDisposition {
    match error {
        TestdEvidenceError::SourcePurged { .. } => TestdStreamDisposition::Purged,
        TestdEvidenceError::SourceRetentionBlocked { .. } => {
            TestdStreamDisposition::RetentionBlocked
        }
        TestdEvidenceError::SourceStale { .. } => TestdStreamDisposition::Stale,
        TestdEvidenceError::SourceUnknownOutcome { .. } => TestdStreamDisposition::UnknownOutcome,
        TestdEvidenceError::SourcePolicyProhibited { .. } => {
            TestdStreamDisposition::PolicyProhibited
        }
        TestdEvidenceError::SourceRedactionFailed { .. } => TestdStreamDisposition::RedactionFailed,
        TestdEvidenceError::SourceUnavailable { .. } => TestdStreamDisposition::SourceUnavailable,
        TestdEvidenceError::LegacyStreamEvidenceUnavailable { .. } => {
            TestdStreamDisposition::LegacyMigrationRequired
        }
        TestdEvidenceError::BindingMismatch { .. }
        | TestdEvidenceError::DenominatorIncomplete { .. }
        | TestdEvidenceError::SourcePartial { .. }
        | TestdEvidenceError::SourceIntegrityBroken { .. }
        | TestdEvidenceError::ReadbackIdentityMismatch { .. }
        | TestdEvidenceError::ReadbackDigestMismatch { .. }
        | TestdEvidenceError::ReadbackLengthMismatch { .. }
        | TestdEvidenceError::ParserNotExecuted { .. }
        | TestdEvidenceError::ParserIncompatible { .. }
        | TestdEvidenceError::ParserFailed { .. }
        | TestdEvidenceError::EvaluatorNotExecuted { .. }
        | TestdEvidenceError::EvaluatorFailed { .. }
        | TestdEvidenceError::EvaluatorInconclusive { .. }
        | TestdEvidenceError::EvaluationStale { .. }
        | TestdEvidenceError::ArtifactBindingMismatch { .. }
        | TestdEvidenceError::ReadbackRequestInvalid { .. } => {
            TestdStreamDisposition::IntegrityBroken
        }
    }
}

/// Validates one retained reference: non-blank, control-free, bounded.
fn validate_reference(field: &'static str, value: Option<&str>) -> Result<(), TestdEvidenceError> {
    match value {
        Some(value)
            if !value.trim().is_empty()
                && value.len() <= MAX_BINDING_REFERENCE_BYTES
                && !value.chars().any(char::is_control) =>
        {
            Ok(())
        }
        _ => Err(TestdEvidenceError::BindingMismatch {
            reason: match field {
                "parser_id" | "parser_revision" => "the parser identity is blank or malformed",
                "evaluator_id" | "evaluator_revision" | "evaluator_property" => {
                    "the evaluator identity is blank or malformed"
                }
                "artifact_binding" => "the artifact binding is blank or malformed",
                "legacy_reference" => "the legacy provenance reference is blank or malformed",
                "locator" => "the source locator is blank or malformed",
                "ready_receipt_ref" => "the ready-receipt identity is blank or malformed",
                "readback_receipt_id" => "the readback receipt identity is blank or malformed",
                "evidence_revision" => "the evidence revision is blank or malformed",
                _ => "a retained reference is blank or malformed",
            },
        }),
    }
}

/// Validates one lowercase SHA-256 digest.
fn validate_digest(field: &'static str, value: &str) -> Result<(), TestdEvidenceError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(TestdEvidenceError::BindingMismatch {
            reason: match field {
                "evidence_identity_sha256" => "the evidence content identity is not a digest",
                "source_sha256" => "the source digest is not a lowercase SHA-256",
                "expected_sha256" => "the expected source digest is not a lowercase SHA-256",
                _ => "a retained digest is not a lowercase SHA-256",
            },
        })
    }
}
