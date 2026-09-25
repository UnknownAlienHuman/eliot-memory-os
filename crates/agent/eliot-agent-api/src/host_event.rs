//! Closed, versioned provider-neutral host-event owner (issue #371, T4 S6).
//!
//! Every admitted normalized host event is a closed, versioned ELIOT
//! observation whose exact producer adapter, provider execution unit, input
//! source, normalized schema, information loss, privacy disposition, ordering
//! boundary, and proof ceiling are machine-checkable.
//!
//! Field ownership in this module:
//!
//! ```text
//! NormalizedHostEventEnvelope      the single current normalized observation;
//!                                  versioned `eliot-agent-api/host-event-v7`.
//! NormalizedHostEventPayload       closed tagged payload family; no
//!                                  `serde_json::Value`, no flattened map, no
//!                                  `Other` escape.
//! HostEventNormalizationReceipt    normalizer identity, source binding, loss
//!                                  manifest, privacy/coverage disposition, and
//!                                  the observation-only proof ceiling.
//! ```
//!
//! Non-goals, enforced structurally by the absence of such fields:
//!
//! - no route authority: the envelope references the exact #369
//!   [`AdmittedRouteReceipt`](crate::AdmittedRouteReceipt) by digest only;
//! - no candidate construction: `CandidateResultAvailable` references the
//!   exact #370 [`AgentResult`](crate::AgentResult) by canonical digest only;
//! - no completion: the ceiling is always
//!   [`ProofCeiling::Observation`](eliot_receipts::ProofCeiling); there is no
//!   `CompletionProof`, Finish, `VerifiedComplete`, or acceptance state here.
//!
//! The legacy [`HostEventEnvelope`](crate::HostEventEnvelope) with its generic
//! `normalized_payload: serde_json::Value` wire is untouched and remains the
//! quarantine boundary for old producers. Old wires never deserialize as this
//! schema: the Rust type is distinct, unknown fields are denied, and the
//! schema version gate rejects the v6 lineage.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CancelReason, CancellationState, ContractError, EventCursor, EventId, ExecutionUnit,
    ProviderExecutionBinding, ProviderObservationLineage, UsageReceipt,
};
use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ClockReading, LowercaseSha256, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_receipts::ProofCeiling;

/// Wire revision of the closed normalized host-event schema. The v6
/// [`HostEventEnvelope`](crate::HostEventEnvelope) wire is untouched; this
/// version gates the new closed owner only.
pub const HOST_EVENT_CONTRACT_VERSION: &str = "eliot-agent-api/host-event-v7";
/// Algorithm/version qualifier required on every canonical source digest bound
/// by this schema. A digest string alone never substitutes for this qualifier
/// plus the immutable restricted source handle.
pub const HOST_EVENT_DIGEST_ALGORITHM: &str = "sha256-canonical-json-v1";
/// Algorithm/version qualifier for digests over exact stored bytes that admit
/// no canonical JSON form: deterministic redacted projections and undecodable
/// sources routed to typed quarantine. The bytes hashed are the immutable
/// stored bytes verbatim (never a reserialization); transport-byte provenance
/// is preserved separately by the durable ingest record, never collapsed into
/// the canonical semantic digest.
pub const HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM: &str = "sha256-raw-bytes-v1";
/// Maximum length of an opaque text field, in Unicode scalar values.
pub const MAX_HOST_EVENT_TEXT_CHARS: usize = 1024;
/// Maximum length of an adapter-sanitized public summary, in Unicode scalar
/// values. Raw provider reasoning, prompts, tool data, and errors never enter
/// these fields; they stay behind the restricted source handle.
pub const MAX_HOST_EVENT_SAFE_TEXT_CHARS: usize = 2048;
/// Maximum number of omitted/lost source fields declared in one receipt.
pub const MAX_HOST_EVENT_OMITTED_FIELDS: usize = 32;
/// Maximum number of normalization warnings carried by one receipt.
pub const MAX_HOST_EVENT_WARNINGS: usize = 16;
/// Maximum number of causal predecessors carried by one envelope.
pub const MAX_HOST_EVENT_PREDECESSORS: usize = 8;

/// Substrings that must never appear in a public normalized payload string.
/// They name restricted source content (secret values, credentials, provider
/// hidden reasoning) that stays behind the restricted source handle per I7.23.
/// Normalizers scan every caller-supplied or wire-derived public string with
/// [`contains_restricted_source_token`] and fail closed before sealing; raw
/// transport-byte scanning stays with the ingest owners.
const RESTRICTED_SOURCE_TOKENS: &[&str] = &[
    "secret",
    "passwd",
    "password",
    "bearer",
    "hidden_reasoning",
    "provider_hidden",
    "api_key",
];

/// Reports whether public payload text carries restricted source content.
/// Matched case-insensitively; a match means the text must stay behind the
/// restricted source handle and never enter the normalized payload.
#[must_use]
pub fn contains_restricted_source_token(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    RESTRICTED_SOURCE_TOKENS
        .iter()
        .any(|token| lowered.contains(token))
}

/// Rejects blank, whitespace-only, control-bearing, or over-long opaque text.
fn validate_text(value: &str, field: &'static str, max_chars: usize) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::EmptyField(field));
    }
    if value.chars().any(char::is_control) {
        return Err(ContractError::EmptyIdentity(field));
    }
    if value.chars().count() > max_chars {
        return Err(ContractError::OversizeField { field });
    }
    Ok(())
}

/// Validates an optional bounded summary. `None` is absent evidence, never an
/// empty-string placeholder.
fn validate_optional_text(
    value: Option<&str>,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ContractError> {
    if let Some(text) = value {
        validate_text(text, field, max_chars)?;
    }
    Ok(())
}

/// Compares two serializable values by their canonical JSON bytes.
fn canonical_eq(left: &impl Serialize, right: &impl Serialize) -> bool {
    match (canonical_json_bytes(left), canonical_json_bytes(right)) {
        (Ok(left_bytes), Ok(right_bytes)) => left_bytes == right_bytes,
        _ => false,
    }
}

/// Opaque restricted/redacted raw-source handle.
///
/// Minted by the restricted source owner, this handle addresses the immutable
/// raw provider bytes (or their redacted projection) without embedding them.
/// It is a distinct type so raw payload strings can never be passed where a
/// handle is required; it carries no credential, prompt, or environment
/// content by construction (there is no field for such content).
#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, JsonSchema, Serialize,
)]
#[serde(transparent)]
pub struct RestrictedRawSourceHandle(String);

impl RestrictedRawSourceHandle {
    /// Constructs a handle, rejecting blank, control-bearing, or over-long
    /// values. A missing handle fails closed at every intake boundary.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_text(&value, "raw_source_handle", MAX_HOST_EVENT_TEXT_CHARS)?;
        Ok(Self(value))
    }

    /// Returns the opaque handle text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Algorithm/version-qualified canonical digest of one immutable source.
///
/// `algorithm` is either [`HOST_EVENT_DIGEST_ALGORITHM`] (sha256 over the
/// canonical JSON bytes of the decoded source message) or
/// [`HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM`] (sha256 over the exact stored
/// bytes, used only for deterministic redacted projections and undecodable
/// sources routed to typed quarantine). An unqualified or otherwise-qualified
/// digest never validates.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedSourceDigest {
    /// Must equal [`HOST_EVENT_DIGEST_ALGORITHM`] or
    /// [`HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM`]; an unqualified or
    /// differently-qualified digest never validates.
    pub algorithm: String,
    /// Canonical digest of the immutable source bytes.
    pub digest: LowercaseSha256,
}

impl QualifiedSourceDigest {
    /// Validates the qualifier and the typed digest form.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.algorithm != HOST_EVENT_DIGEST_ALGORITHM
            && self.algorithm != HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM
        {
            return Err(ContractError::InvalidDigest {
                field: "digest_algorithm",
            });
        }
        Ok(())
    }

    /// Recomputes this digest against the canonical JSON bytes of the decoded
    /// source message and rejects any mismatch. The qualifier must be
    /// [`HOST_EVENT_DIGEST_ALGORITHM`]: a raw-bytes digest never verifies
    /// against canonical message bytes, and a canonical digest never verifies
    /// without recomputation. Normalizers and the durable ingest journal call
    /// this with the bytes they actually decoded instead of trusting a copied
    /// digest string.
    pub fn verify_canonical_message(&self, message: &impl Serialize) -> Result<(), ContractError> {
        if self.algorithm != HOST_EVENT_DIGEST_ALGORITHM {
            return Err(ContractError::InvalidDigest {
                field: "digest_algorithm",
            });
        }
        let canonical = canonical_json_bytes(message).map_err(|_| ContractError::DigestMismatch)?;
        if sha256_hex(&canonical) != self.digest.as_str() {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }

    /// Recomputes this digest against exact stored bytes (deterministic
    /// redacted projections, undecodable sources routed to typed quarantine)
    /// and rejects any mismatch. The qualifier must be
    /// [`HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM`].
    pub fn verify_raw_bytes(&self, bytes: &[u8]) -> Result<(), ContractError> {
        if self.algorithm != HOST_EVENT_RAW_BYTES_DIGEST_ALGORITHM {
            return Err(ContractError::InvalidDigest {
                field: "digest_algorithm",
            });
        }
        if sha256_hex(bytes) != self.digest.as_str() {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }
}

/// Restricted raw-source binding: handle plus qualified digest together. A
/// handle without its digest, or a digest without its handle, fails closed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSourceRecord {
    /// Immutable restricted/redacted source handle.
    pub handle: RestrictedRawSourceHandle,
    /// Algorithm/version-qualified canonical digest of the source bytes.
    pub digest: QualifiedSourceDigest,
}

impl RawSourceRecord {
    /// Validates the handle/digest binding.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(
            self.handle.as_str(),
            "raw_source_handle",
            MAX_HOST_EVENT_TEXT_CHARS,
        )?;
        self.digest.validate()
    }
}

/// Session-lifecycle transition observed on a provider-native session. This is
/// session/thread-scoped evidence only and carries no attempt authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionLifecycleTransition {
    Started,
    Resumed,
    Suspended,
    Closed,
}

/// Session-lifecycle observation. Valid only under session lineage; it cannot
/// update attempt terminality, usage, candidate results, or completion.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLifecycleObservation {
    /// The observed session transition.
    pub transition: SessionLifecycleTransition,
    /// Optional bounded session detail reference (locator-class, never raw
    /// provider state).
    pub detail_ref: Option<String>,
}

impl SessionLifecycleObservation {
    fn validate(&self) -> Result<(), ContractError> {
        validate_optional_text(
            self.detail_ref.as_deref(),
            "detail_ref",
            MAX_HOST_EVENT_TEXT_CHARS,
        )
    }
}

/// Execution-unit started observation. Binds the exact execution unit by
/// value; the unit identity is never parsed from provider text.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStartedObservation {
    /// The exact execution unit that started, equal by value to the bound unit.
    pub execution_unit: ExecutionUnit,
    /// Bounded start-correlation reference minted by the adapter.
    pub start_ref: String,
}

impl ExecutionStartedObservation {
    fn validate(&self) -> Result<(), ContractError> {
        self.execution_unit.validate()?;
        validate_text(&self.start_ref, "start_ref", MAX_HOST_EVENT_TEXT_CHARS)
    }
}

/// Assistant output delta observation. Carries a bounded size summary only;
/// raw model output stays behind the restricted source handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantDeltaObservation {
    /// Number of delta characters observed in this event.
    pub delta_chars: u64,
    /// Whether the delta was truncated before the restricted source record.
    pub truncated: bool,
}

/// Reasoning-summary observation. Raw reasoning stays behind the restricted
/// source handle; only the bounded size summary is public.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningSummaryObservation {
    /// Number of reasoning-summary characters observed in this event.
    pub summary_chars: u64,
    /// Whether the summary was truncated before the restricted source record.
    pub truncated: bool,
}

/// Tool outcome class. `Unknown` preserves the outcome gap explicitly and
/// never upgrades to success.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolOutcomeClass {
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}

/// Tool invocation observation. Arguments stay behind the restricted source
/// handle; the digest binds them without exposing them.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInvocationObservation {
    /// Provider-neutral tool name as classified by the adapter.
    pub tool_name: String,
    /// Bounded invocation correlation reference minted by the adapter.
    pub invocation_ref: String,
    /// Canonical digest of the exact invocation arguments.
    pub arguments_digest: LowercaseSha256,
}

impl ToolInvocationObservation {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.tool_name, "tool_name", MAX_HOST_EVENT_TEXT_CHARS)?;
        validate_text(
            &self.invocation_ref,
            "invocation_ref",
            MAX_HOST_EVENT_TEXT_CHARS,
        )
    }
}

/// Tool outcome observation. Results stay behind the restricted source handle;
/// the digest binds them without exposing them.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOutcomeObservation {
    /// Provider-neutral tool name as classified by the adapter.
    pub tool_name: String,
    /// Invocation correlation reference matching the invocation observation.
    pub invocation_ref: String,
    /// Classified outcome; never inferred success.
    pub outcome: ToolOutcomeClass,
    /// Canonical digest of the exact tool result bytes.
    pub result_digest: LowercaseSha256,
    /// Optional adapter-sanitized public summary.
    pub safe_summary: Option<String>,
}

impl ToolOutcomeObservation {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.tool_name, "tool_name", MAX_HOST_EVENT_TEXT_CHARS)?;
        validate_text(
            &self.invocation_ref,
            "invocation_ref",
            MAX_HOST_EVENT_TEXT_CHARS,
        )?;
        validate_optional_text(
            self.safe_summary.as_deref(),
            "safe_summary",
            MAX_HOST_EVENT_SAFE_TEXT_CHARS,
        )
    }
}

/// Checkpoint observation. The checkpoint body stays behind the restricted
/// source handle; the digest binds it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointObservation {
    /// Bounded checkpoint reference minted by the adapter.
    pub checkpoint_ref: String,
    /// Canonical digest of the exact checkpoint bytes.
    pub checkpoint_digest: LowercaseSha256,
}

impl CheckpointObservation {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text(
            &self.checkpoint_ref,
            "checkpoint_ref",
            MAX_HOST_EVENT_TEXT_CHARS,
        )
    }
}

/// Warning observation with an adapter-sanitized public summary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarningObservation {
    /// Stable warning code classified by the adapter.
    pub code: String,
    /// Adapter-sanitized public summary.
    pub summary: String,
}

impl WarningObservation {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.code, "code", MAX_HOST_EVENT_TEXT_CHARS)?;
        validate_text(&self.summary, "summary", MAX_HOST_EVENT_SAFE_TEXT_CHARS)
    }
}

/// Error observation with an adapter-sanitized public summary. Raw provider
/// errors stay behind the restricted source handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorObservation {
    /// Stable error code classified by the adapter.
    pub code: String,
    /// Adapter-sanitized public summary; never raw provider error content.
    pub safe_summary: String,
}

impl ErrorObservation {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.code, "code", MAX_HOST_EVENT_TEXT_CHARS)?;
        validate_text(
            &self.safe_summary,
            "safe_summary",
            MAX_HOST_EVENT_SAFE_TEXT_CHARS,
        )
    }
}

/// Cancellation observation. Preserves the #361/#370 reconciliation identity
/// by lineage; it cannot release ownership, authorize retry, or become
/// terminal success.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationObservation {
    /// Classified cancellation reason.
    pub reason: CancelReason,
    /// Observed cancellation state. `NotRequested` is rejected: a present
    /// observation means cancellation was observed.
    pub observed_state: CancellationState,
}

impl CancellationObservation {
    fn validate(&self) -> Result<(), ContractError> {
        if self.observed_state == CancellationState::NotRequested {
            return Err(ContractError::InvalidRouteDisposition);
        }
        Ok(())
    }
}

/// Provider execution terminal status. The `Observed` suffix is structural:
/// a provider terminal notification is only an observation of the exact
/// execution unit, never task completion and never a candidate result.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderTerminalStatus {
    CompletedObserved,
    FailedObserved,
    CancelledObserved,
}

/// Provider execution terminal observation. Records only that the provider
/// reported a terminal state for the exact bound execution unit. A terminal
/// event alone creates no candidate result receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTerminalObservation {
    /// The reported terminal status, observation-scoped by construction.
    pub status: ProviderTerminalStatus,
    /// Bounded terminal-correlation reference minted by the adapter.
    pub terminal_ref: String,
}

impl ProviderTerminalObservation {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text(
            &self.terminal_ref,
            "terminal_ref",
            MAX_HOST_EVENT_TEXT_CHARS,
        )
    }
}

/// Candidate-result-available reference (issue #370 plane).
///
/// References the exact admitted #370 [`AgentResult`](crate::AgentResult) by
/// its canonical digest plus the governing #369 admission digest. It embeds
/// no artifacts, evidence, or provider text, so arbitrary provider output can
/// never synthesize a candidate result through this event.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateResultReference {
    /// Attempt the referenced candidate result was submitted for.
    pub attempt_id: AgentAttemptId,
    /// Canonical digest of the exact #370 candidate-result bytes (see
    /// [`candidate_result_digest_for`]).
    pub result_digest: LowercaseSha256,
    /// Digest of the governing #369 admitted-route receipt.
    pub admitted_route_digest: LowercaseSha256,
}

/// Computes the canonical digest of exact #370 candidate-result bytes. The
/// [`CandidateResultReference`] stores this value; validators recompute it
/// from the result instead of trusting a copied string.
pub fn candidate_result_digest_for(
    result: &crate::AgentResult,
) -> Result<LowercaseSha256, serde_json::Error> {
    serde_json::from_value(serde_json::Value::String(sha256_hex(
        &canonical_json_bytes(result)?,
    )))
}

impl CandidateResultReference {
    /// Verifies this reference against the exact admitted #370 candidate
    /// result and its governing #369 admission: the attempt must match the
    /// result's attempt, the admission digest must match the governing
    /// admission, and the result digest is recomputed from the result bytes
    /// instead of trusting the copied string. An arbitrary result digest
    /// never verifies.
    pub fn verify_against(
        &self,
        result: &crate::AgentResult,
        admission: &crate::AdmittedRouteReceipt,
    ) -> Result<(), ContractError> {
        if self.attempt_id != result.attempt_id {
            return Err(ContractError::BindingMismatch);
        }
        if self.admitted_route_digest != admission.self_digest {
            return Err(ContractError::BindingMismatch);
        }
        let recomputed =
            candidate_result_digest_for(result).map_err(|_| ContractError::DigestMismatch)?;
        if recomputed != self.result_digest {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }
}

/// Why an unsupported provider event was quarantined instead of normalized.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnsupportedEventReason {
    UnknownMethod,
    UnsupportedVersion,
    SourceDecodeFailure,
}

/// Quarantined unsupported-provider-event observation.
///
/// Retained only as typed quarantine evidence carrying bounded
/// namespace/version/source/digest/loss/privacy facts. It cannot enter
/// policy, authority, route, candidate-result, Finish, or closure logic until
/// a reviewed typed normalizer exists.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedEventObservation {
    /// Provider-namespace marker classified by the adapter (method family,
    /// never raw provider JSON).
    pub source_namespace: String,
    /// Provider event version when one was advertised.
    pub source_version: Option<String>,
    /// Why the event was quarantined.
    pub reason: UnsupportedEventReason,
    /// Optional bounded quarantine detail reference.
    pub detail_ref: Option<String>,
}

impl UnsupportedEventObservation {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text(
            &self.source_namespace,
            "source_namespace",
            MAX_HOST_EVENT_TEXT_CHARS,
        )?;
        validate_optional_text(
            self.source_version.as_deref(),
            "source_version",
            MAX_HOST_EVENT_TEXT_CHARS,
        )?;
        validate_optional_text(
            self.detail_ref.as_deref(),
            "detail_ref",
            MAX_HOST_EVENT_TEXT_CHARS,
        )
    }
}

/// Closed tagged normalized payload family.
///
/// Every current event kind has exactly one tagged typed payload schema: the
/// tag and the payload cannot mismatch by construction, and there is no
/// `serde_json::Value`, flattened arbitrary map, raw provider payload, or
/// method-name passthrough anywhere in this family.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "payload_kind",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum NormalizedHostEventPayload {
    SessionLifecycle(SessionLifecycleObservation),
    ExecutionStarted(ExecutionStartedObservation),
    AssistantDelta(AssistantDeltaObservation),
    ReasoningSummary(ReasoningSummaryObservation),
    ToolInvocation(ToolInvocationObservation),
    ToolOutcome(ToolOutcomeObservation),
    Checkpoint(CheckpointObservation),
    Usage(UsageReceipt),
    Warning(WarningObservation),
    Error(ErrorObservation),
    CancellationObserved(CancellationObservation),
    ProviderTerminalObserved(ProviderTerminalObservation),
    CandidateResultAvailable(CandidateResultReference),
    UnsupportedQuarantined(UnsupportedEventObservation),
}

impl NormalizedHostEventPayload {
    /// Returns whether this payload requires exact execution-unit lineage. A
    /// payload returning `false` is session-scoped evidence and can never
    /// carry attempt authority.
    #[must_use]
    pub const fn requires_execution_unit(&self) -> bool {
        match self {
            Self::SessionLifecycle(_) | Self::UnsupportedQuarantined(_) => false,
            Self::ExecutionStarted(_)
            | Self::AssistantDelta(_)
            | Self::ReasoningSummary(_)
            | Self::ToolInvocation(_)
            | Self::ToolOutcome(_)
            | Self::Checkpoint(_)
            | Self::Usage(_)
            | Self::Warning(_)
            | Self::Error(_)
            | Self::CancellationObserved(_)
            | Self::ProviderTerminalObserved(_)
            | Self::CandidateResultAvailable(_) => true,
        }
    }

    /// Returns whether this payload is session-lifecycle scoped. Session
    /// lifecycle is the only payload that cannot ride execution-unit lineage:
    /// it observes the session, not the unit.
    #[must_use]
    pub const fn is_session_lifecycle(&self) -> bool {
        matches!(self, Self::SessionLifecycle(_))
    }

    /// Validates payload shape: bounded lengths and per-variant coherence.
    /// Lineage pairing is enforced by the envelope validators, not here.
    /// Unit-only payloads with no shape beyond their types
    /// (`AssistantDelta`, `ReasoningSummary`, `Usage`) and the digest-only
    /// [`CandidateResultReference`] (whose attempt/digest agreement is
    /// enforced by [`NormalizedHostEventEnvelope::validate_for_lineage`])
    /// validate structurally.
    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::AssistantDelta(_)
            | Self::ReasoningSummary(_)
            | Self::Usage(_)
            | Self::CandidateResultAvailable(_) => Ok(()),
            Self::SessionLifecycle(observation) => observation.validate(),
            Self::ExecutionStarted(observation) => observation.validate(),
            Self::ToolInvocation(observation) => observation.validate(),
            Self::ToolOutcome(observation) => observation.validate(),
            Self::Checkpoint(observation) => observation.validate(),
            Self::Warning(observation) => observation.validate(),
            Self::Error(observation) => observation.validate(),
            Self::CancellationObserved(observation) => observation.validate(),
            Self::ProviderTerminalObserved(observation) => observation.validate(),
            Self::UnsupportedQuarantined(observation) => observation.validate(),
        }
    }

    /// Returns every public text string carried by this payload: bounded
    /// summaries, classifier codes, correlation references, and quarantine
    /// facts. Raw provider content never appears here by construction (counts,
    /// digests, and enums carry no text), so normalizers sanitize exactly
    /// these strings against the restricted source before sealing.
    #[must_use]
    pub fn public_strings(&self) -> Vec<&str> {
        match self {
            Self::AssistantDelta(_)
            | Self::ReasoningSummary(_)
            | Self::Usage(_)
            | Self::CandidateResultAvailable(_)
            | Self::CancellationObserved(_) => Vec::new(),
            Self::SessionLifecycle(observation) => {
                observation.detail_ref.as_deref().into_iter().collect()
            }
            Self::ExecutionStarted(observation) => vec![observation.start_ref.as_str()],
            Self::ToolInvocation(observation) => vec![
                observation.tool_name.as_str(),
                observation.invocation_ref.as_str(),
            ],
            Self::ToolOutcome(observation) => {
                let mut strings = vec![
                    observation.tool_name.as_str(),
                    observation.invocation_ref.as_str(),
                ];
                strings.extend(observation.safe_summary.as_deref());
                strings
            }
            Self::Checkpoint(observation) => vec![observation.checkpoint_ref.as_str()],
            Self::Warning(observation) => {
                vec![observation.code.as_str(), observation.summary.as_str()]
            }
            Self::Error(observation) => {
                vec![observation.code.as_str(), observation.safe_summary.as_str()]
            }
            Self::ProviderTerminalObserved(observation) => {
                vec![observation.terminal_ref.as_str()]
            }
            Self::UnsupportedQuarantined(observation) => {
                let mut strings = vec![observation.source_namespace.as_str()];
                strings.extend(observation.source_version.as_deref());
                strings.extend(observation.detail_ref.as_deref());
                strings
            }
        }
    }

    /// Returns the stable closed-payload tag (`payload_kind` wire spelling)
    /// for this payload. The durable-to-intake conversion preserves it
    /// explicitly so a payload can never change kind across the boundary.
    #[must_use]
    pub const fn payload_type_tag(&self) -> &'static str {
        match self {
            Self::SessionLifecycle(_) => "SESSION_LIFECYCLE",
            Self::ExecutionStarted(_) => "EXECUTION_STARTED",
            Self::AssistantDelta(_) => "ASSISTANT_DELTA",
            Self::ReasoningSummary(_) => "REASONING_SUMMARY",
            Self::ToolInvocation(_) => "TOOL_INVOCATION",
            Self::ToolOutcome(_) => "TOOL_OUTCOME",
            Self::Checkpoint(_) => "CHECKPOINT",
            Self::Usage(_) => "USAGE",
            Self::Warning(_) => "WARNING",
            Self::Error(_) => "ERROR",
            Self::CancellationObserved(_) => "CANCELLATION_OBSERVED",
            Self::ProviderTerminalObserved(_) => "PROVIDER_TERMINAL_OBSERVED",
            Self::CandidateResultAvailable(_) => "CANDIDATE_RESULT_AVAILABLE",
            Self::UnsupportedQuarantined(_) => "UNSUPPORTED_QUARANTINED",
        }
    }
}

/// Derives the stable event identity for one normalized input: `sha256` over
/// the canonical JSON bytes of the adapter identity/version, the exact
/// lineage, the sequence, the closed typed payload, and the qualified source
/// digest. Same input, adapter version, and lineage always derive the same
/// identity; changing any bound field changes it. The durable-to-intake
/// conversion carries this derivation alongside the owner-minted `event_id`
/// so forensic replay can distinguish a re-minted identity from a stable one.
pub fn stable_event_id_for(
    adapter_identity: &str,
    adapter_version: &str,
    lineage: &ProviderObservationLineage,
    sequence: u64,
    payload: &NormalizedHostEventPayload,
    source_digest: &QualifiedSourceDigest,
) -> Result<EventId, ContractError> {
    let canonical = canonical_json_bytes(&(
        adapter_identity,
        adapter_version,
        lineage,
        sequence,
        payload,
        source_digest,
    ))
    .map_err(|_| ContractError::DigestMismatch)?;
    EventId::new(sha256_hex(&canonical))
}

/// Disposition of unsupported provider fields or versions encountered during
/// normalization. Redaction, omission, truncation, decode failure, and
/// unsupported version are distinct typed dispositions.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnsupportedDisposition {
    None,
    UnsupportedMethodQuarantined,
    UnsupportedVersionDeferred,
    SourceDecodeFailure,
}

/// Privacy/redaction/disclosure class of the normalized payload.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostEventPrivacyClass {
    PublicSummary,
    RedactedSummary,
    RestrictedHandleOnly,
}

/// Coverage of the normalization over its input source.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormalizationCoverage {
    Complete,
    LossyOmission,
    TruncatedSource,
}

/// Normalization receipt: the machine-checkable binding between the immutable
/// input source, the normalizer version, the information loss, and the typed
/// output digest.
///
/// The proof ceiling is always
/// [`ProofCeiling::Observation`](eliot_receipts::ProofCeiling):
/// observation-only, never Finish or acceptance.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEventNormalizationReceipt {
    /// Normalizer/adapter identity. Must equal the envelope's
    /// `producer_adapter_identity`.
    pub normalizer_identity: String,
    /// Normalizer/adapter contract version. Must equal the envelope's
    /// `adapter_contract_version`.
    pub normalizer_version: String,
    /// Input restricted/redacted source handle. Must equal the envelope's raw
    /// source handle.
    pub input_handle: RestrictedRawSourceHandle,
    /// Qualified canonical digest of the input source bytes. Must equal the
    /// envelope's raw source digest.
    pub input_digest: QualifiedSourceDigest,
    /// Output event schema version. Must equal
    /// [`HOST_EVENT_CONTRACT_VERSION`].
    pub output_schema_version: String,
    /// Canonical digest of the normalized envelope (see
    /// [`NormalizedHostEventEnvelope::compute_digest`]). Recomputed by every
    /// validator; an unchecked copy is rejected.
    pub output_digest: LowercaseSha256,
    /// Declared omitted/lost/approximated source fields. Empty exactly when
    /// `coverage` is `Complete`: an empty loss manifest is not accepted when
    /// source fields were discarded, and a non-empty manifest is not accepted
    /// for a complete normalization.
    pub omitted_fields: Vec<String>,
    /// Normalization warnings. Bounded; never raw provider content.
    pub warnings: Vec<String>,
    /// Unsupported-field/version disposition.
    pub unsupported_disposition: UnsupportedDisposition,
    /// Privacy/redaction/disclosure class of the normalized payload.
    pub privacy_class: HostEventPrivacyClass,
    /// Coverage/gap disposition of the normalization.
    pub coverage: NormalizationCoverage,
    /// Proof ceiling. Must be
    /// [`ProofCeiling::Observation`](eliot_receipts::ProofCeiling).
    pub proof_ceiling: ProofCeiling,
}

/// Delivery/coverage disposition of the observation transport. Transport
/// identity is not evidence meaning: a best-effort drop never fabricates a
/// durable observation, and a replay never advances durable cursors.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostEventDeliveryDisposition {
    DurableOrdered,
    BestEffortOrdered,
    Replay,
}

/// Replay outcome of one envelope against a previously accepted envelope with
/// the same event identity. Returned, never panicked: an identical replay is
/// idempotent, while a conflicting same-ID replay is quarantined.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HostEventReplayDisposition {
    IdempotentReplay,
    Quarantined { reason: HostEventQuarantineReason },
}

/// Why a same-ID replay conflicts with its accepted predecessor.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostEventQuarantineReason {
    ConflictingPayload,
    ConflictingLineage,
    ConflictingNormalization,
    ConflictingSource,
    ConflictingFraming,
}

/// Closed, versioned normalized host-event envelope (T4 S6 owner).
///
/// `schema_version` is always [`HOST_EVENT_CONTRACT_VERSION`]. `event_id` and
/// `cursor` come from the single post-R1 identity owner. `lineage` reuses the
/// existing [`ProviderObservationLineage`] (session observation or exact
/// execution-unit observation): no string/JSON parsing, no new attempt
/// invention. `observed_at` is the typed [`ClockReading`] observation;
/// sequence/cursor/fence provide causal order and a raw wall clock never
/// authorizes anything.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedHostEventEnvelope {
    /// Wire/contract version bound into the normalization digest.
    pub schema_version: String,
    /// Event identity from the post-R1 owner.
    pub event_id: EventId,
    /// Resume cursor from the post-R1 owner.
    pub cursor: EventCursor,
    /// Session-only or exact execution-unit provenance. Session observation
    /// carries no attempt authority.
    pub lineage: ProviderObservationLineage,
    /// Producer adapter identity (for example `eliot-agent-acp`).
    pub producer_adapter_identity: String,
    /// Producer adapter contract version.
    pub adapter_contract_version: String,
    /// Monotonic sequence within the bound execution unit or session stream.
    /// Must be nonzero.
    pub sequence: u64,
    /// Causal predecessor event identities. Bounded; never contains the
    /// event's own identity.
    pub causal_predecessors: Vec<EventId>,
    /// Closed typed payload. Exactly one schema per kind by construction.
    pub payload: NormalizedHostEventPayload,
    /// Reference to the exact #369 admitted-route receipt by digest. `Some`
    /// exactly for execution-unit lineage (must equal the admission's
    /// `self_digest`); `None` for session-only observations, which carry no
    /// admission reference and therefore no route authority.
    pub admitted_route_digest: Option<LowercaseSha256>,
    /// Restricted raw-source binding: handle plus qualified digest.
    pub raw_source: RawSourceRecord,
    /// Normalization receipt binding source, loss, privacy, and ceiling.
    pub normalization: HostEventNormalizationReceipt,
    /// Typed observation time. Unknown stays unknown; wall time never
    /// advances sequence, cursor, fence, attempt state, or expiry authority.
    pub observed_at: ClockReading,
    /// Delivery/coverage disposition of this observation.
    pub delivery: HostEventDeliveryDisposition,
}

impl NormalizedHostEventEnvelope {
    /// Computes the canonical output digest: `sha256_hex` over the canonical
    /// JSON bytes of this envelope minus the receipt's `output_digest` field.
    /// Minting normalizers store the result before publishing; validators
    /// recompute it instead of trusting a copied string.
    pub fn compute_digest(&self) -> Result<LowercaseSha256, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(object) = value.as_object_mut()
            && let Some(normalization) = object.get_mut("normalization")
            && let Some(receipt) = normalization.as_object_mut()
        {
            receipt.remove("output_digest");
        }
        serde_json::from_value(serde_json::Value::String(sha256_hex(
            &canonical_json_bytes(&value)?,
        )))
    }

    /// Seals this envelope by recomputing its canonical output digest into
    /// the embedded normalization receipt.
    pub fn seal(&mut self) -> Result<(), serde_json::Error> {
        self.normalization.output_digest = self.compute_digest()?;
        Ok(())
    }

    /// Validates envelope framing without consulting admission context: schema
    /// version, identities, adapter binding, predecessors, payload shape,
    /// route-reference presence, raw-source binding, receipt coherence
    /// (identity/version/digest/loss/privacy/ceiling), and clock coherence.
    /// Recorded lineage/admission agreement is [`Self::validate_for_lineage`];
    /// session-only validation is [`Self::validate_as_session_observation`].
    fn validate_framing(&self) -> Result<(), ContractError> {
        if self.schema_version != HOST_EVENT_CONTRACT_VERSION {
            return Err(ContractError::UnknownContractVersion);
        }
        validate_text(
            self.event_id.as_str(),
            "event_id",
            MAX_HOST_EVENT_TEXT_CHARS,
        )?;
        validate_text(self.cursor.as_str(), "cursor", MAX_HOST_EVENT_TEXT_CHARS)?;
        if self.sequence == 0 {
            return Err(ContractError::ZeroLimit { field: "sequence" });
        }
        validate_text(
            &self.producer_adapter_identity,
            "producer_adapter_identity",
            MAX_HOST_EVENT_TEXT_CHARS,
        )?;
        validate_text(
            &self.adapter_contract_version,
            "adapter_contract_version",
            MAX_HOST_EVENT_TEXT_CHARS,
        )?;
        if self.causal_predecessors.len() > MAX_HOST_EVENT_PREDECESSORS {
            return Err(ContractError::OversizeField {
                field: "causal_predecessors",
            });
        }
        if self.causal_predecessors.contains(&self.event_id) {
            return Err(ContractError::NonMonotonicEvent);
        }
        self.payload.validate()?;
        match &self.lineage {
            ProviderObservationLineage::SessionObservation(observation) => {
                observation.validate()?;
                if self.admitted_route_digest.is_some() {
                    return Err(ContractError::BindingMismatch);
                }
            }
            ProviderObservationLineage::ExecutionUnitObservation(observation) => {
                observation.validate()?;
                if self.admitted_route_digest.is_none() {
                    return Err(ContractError::BindingMismatch);
                }
                if observation.cursor != self.cursor || observation.sequence != self.sequence {
                    return Err(ContractError::BindingMismatch);
                }
            }
        }
        self.raw_source.validate()?;
        self.validate_receipt_coherence()?;
        self.observed_at
            .validate()
            .map_err(|_| ContractError::InvalidClock)?;
        if self
            .observed_at
            .valid_time_ms
            .is_some_and(|value| value < 0)
            || self
                .observed_at
                .known_time_ms
                .is_some_and(|value| value < 0)
        {
            return Err(ContractError::InvalidClock);
        }
        Ok(())
    }

    /// Validates the embedded normalization receipt against this envelope:
    /// normalizer identity/version agreement, input source agreement, output
    /// schema/digest agreement (recomputed), the loss-manifest invariant,
    /// the quarantine/payload coherence, bounded manifests, and the
    /// observation-only proof ceiling.
    fn validate_receipt_coherence(&self) -> Result<(), ContractError> {
        let receipt = &self.normalization;
        if receipt.normalizer_identity != self.producer_adapter_identity
            || receipt.normalizer_version != self.adapter_contract_version
        {
            return Err(ContractError::DigestMismatch);
        }
        if receipt.input_handle != self.raw_source.handle
            || receipt.input_digest != self.raw_source.digest
        {
            return Err(ContractError::DigestMismatch);
        }
        if receipt.output_schema_version != HOST_EVENT_CONTRACT_VERSION
            || self.schema_version != HOST_EVENT_CONTRACT_VERSION
        {
            return Err(ContractError::UnknownContractVersion);
        }
        let computed = self
            .compute_digest()
            .map_err(|_| ContractError::DigestMismatch)?;
        if computed != receipt.output_digest {
            return Err(ContractError::DigestMismatch);
        }
        let lossy = receipt.coverage != NormalizationCoverage::Complete;
        if lossy == receipt.omitted_fields.is_empty() {
            return Err(ContractError::InvalidRouteDisposition);
        }
        if receipt.omitted_fields.len() > MAX_HOST_EVENT_OMITTED_FIELDS {
            return Err(ContractError::OversizeField {
                field: "omitted_fields",
            });
        }
        for field in &receipt.omitted_fields {
            validate_text(field, "omitted_fields", MAX_HOST_EVENT_TEXT_CHARS)?;
        }
        if receipt.warnings.len() > MAX_HOST_EVENT_WARNINGS {
            return Err(ContractError::OversizeField { field: "warnings" });
        }
        for warning in &receipt.warnings {
            validate_text(warning, "warnings", MAX_HOST_EVENT_SAFE_TEXT_CHARS)?;
        }
        let quarantined = matches!(
            self.payload,
            NormalizedHostEventPayload::UnsupportedQuarantined(_)
        );
        if quarantined == (receipt.unsupported_disposition == UnsupportedDisposition::None) {
            return Err(ContractError::InvalidRouteDisposition);
        }
        if receipt.proof_ceiling != ProofCeiling::Observation {
            return Err(ContractError::InsufficientAuthority);
        }
        Ok(())
    }

    /// Validates a session-only observation: framing plus the requirement
    /// that the payload carries no attempt authority and no admission
    /// reference. Session events serialize without fabricated attempt
    /// authority and cannot update attempt usage, terminality, candidate
    /// results, or completion.
    pub fn validate_as_session_observation(&self) -> Result<(), ContractError> {
        self.validate_framing()?;
        if !matches!(
            self.lineage,
            ProviderObservationLineage::SessionObservation(_)
        ) {
            return Err(ContractError::BindingMismatch);
        }
        if self.payload.requires_execution_unit() {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }

    /// Validates this envelope against the recorded lineage and admission
    /// contexts: the recorded #361 [`ProviderExecutionBinding`] and the
    /// recorded #369 [`AdmittedRouteReceipt`](crate::AdmittedRouteReceipt).
    ///
    /// Enforced, in order: framing (schema version, identities, payload
    /// shape, receipt coherence, clock); session lineage can never carry
    /// attempt authority here (use
    /// [`Self::validate_as_session_observation`]); session-lifecycle payloads
    /// cannot ride execution-unit lineage; the lineage binding must equal the
    /// recorded binding exactly (wrong attempt, binding, fence, generation,
    /// or cursor fails before any mutation); the envelope's #369
    /// route reference must equal the recorded admission digest; and the
    /// recorded binding must agree with the recorded admission on
    /// attempt/lease/fence/generation/route, mirroring the #370
    /// `validate_for_binding` linkage. Causal-predecessor (parent) agreement
    /// has no context at this boundary and is enforced where the mutation
    /// happens instead: the durable ingest journal rejects a staged record
    /// whose carried predecessors diverge from the envelope's
    /// `causal_predecessors` before any cursor moves.
    ///
    /// This constructs no route authority (the admission digest is referenced
    /// only), no candidate result (a result reference is digest-checked
    /// only), and no `CompletionProof`, Finish, or `VerifiedComplete` state.
    pub fn validate_for_lineage(
        &self,
        binding: &ProviderExecutionBinding,
        admission: &crate::AdmittedRouteReceipt,
    ) -> Result<(), ContractError> {
        self.validate_framing()?;
        let observation = match &self.lineage {
            ProviderObservationLineage::SessionObservation(_) => {
                return Err(ContractError::BindingMismatch);
            }
            ProviderObservationLineage::ExecutionUnitObservation(observation) => observation,
        };
        if self.payload.is_session_lifecycle() {
            return Err(ContractError::BindingMismatch);
        }
        binding.validate_internal()?;
        admission.validate()?;
        if observation.binding != *binding {
            return Err(ContractError::BindingMismatch);
        }
        if self.admitted_route_digest.as_ref() != Some(&admission.self_digest) {
            return Err(ContractError::BindingMismatch);
        }
        if binding.attempt_id != admission.attempt_id
            || binding.lease_id != admission.lease_id
            || binding.state_fence != admission.state_fence
            || binding.runtime_generation != admission.runtime_generation
            || binding.route != admission.requested_route
        {
            return Err(ContractError::BindingMismatch);
        }
        if let NormalizedHostEventPayload::CandidateResultAvailable(reference) = &self.payload
            && (reference.attempt_id != binding.attempt_id
                || reference.admitted_route_digest != admission.self_digest)
        {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }

    /// Checks this envelope against a previously accepted envelope with the
    /// same event identity. An identical replay (same event/source/output
    /// identity and digest) is [`HostEventReplayDisposition::IdempotentReplay`];
    /// the same event identity with different source bytes, typed payload,
    /// lineage, normalization receipt, or privacy/loss facts is quarantined
    /// with its first differing dimension. A different event identity is not
    /// a replay at all and fails with [`ContractError::BindingMismatch`].
    pub fn check_replay_against(
        &self,
        previous: &Self,
    ) -> Result<HostEventReplayDisposition, ContractError> {
        self.validate_framing()?;
        previous.validate_framing()?;
        if self.event_id != previous.event_id {
            return Err(ContractError::BindingMismatch);
        }
        if canonical_eq(self, previous) {
            return Ok(HostEventReplayDisposition::IdempotentReplay);
        }
        if !canonical_eq(&self.payload, &previous.payload) {
            return Ok(HostEventReplayDisposition::Quarantined {
                reason: HostEventQuarantineReason::ConflictingPayload,
            });
        }
        if !canonical_eq(&self.lineage, &previous.lineage) {
            return Ok(HostEventReplayDisposition::Quarantined {
                reason: HostEventQuarantineReason::ConflictingLineage,
            });
        }
        if !canonical_eq(&self.raw_source, &previous.raw_source) {
            return Ok(HostEventReplayDisposition::Quarantined {
                reason: HostEventQuarantineReason::ConflictingSource,
            });
        }
        if !canonical_eq(&self.normalization, &previous.normalization) {
            return Ok(HostEventReplayDisposition::Quarantined {
                reason: HostEventQuarantineReason::ConflictingNormalization,
            });
        }
        Ok(HostEventReplayDisposition::Quarantined {
            reason: HostEventQuarantineReason::ConflictingFraming,
        })
    }
}

/// Durable-to-intake conversion view for one committed journal record (issues
/// #371 W7/A27).
///
/// The ACP durable journal commits the raw/hash record, the normalized
/// envelope, and the disposition together; the coordinator intake observes the
/// envelope plus its sealed receipt. This neutral view is the production edge
/// between them: the journal mints it only for committed records, and the
/// coordinator intake consumes it only after re-verifying every preserved
/// fact. Identity, sequence, producer generation, `StateFence`, causal
/// predecessors, closed payload kind, delivery class, and acknowledgement
/// state travel as explicit fields — never re-derived, never dropped — plus
/// the stable event identity derived from the normalized input and the full
/// envelope/receipt pair for the intake equality and digest checks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedHostEventIntake {
    /// Owner-minted event identity, preserved verbatim.
    pub event_id: EventId,
    /// Owner-minted resume cursor, preserved verbatim.
    pub cursor: EventCursor,
    /// Monotonic sequence, preserved verbatim.
    pub sequence: u64,
    /// Producer runtime generation. `Some` exactly for execution-unit lineage.
    pub runtime_generation: Option<ResourceGeneration>,
    /// Current `StateFence`. `Some` exactly for execution-unit lineage.
    pub state_fence: Option<StateFence>,
    /// Causal predecessor identities, preserved verbatim.
    pub causal_predecessors: Vec<EventId>,
    /// Closed payload kind tag (see
    /// [`NormalizedHostEventPayload::payload_type_tag`]).
    pub payload_type: String,
    /// Delivery/coverage disposition, preserved verbatim.
    pub delivery: HostEventDeliveryDisposition,
    /// Whether the journal acknowledged this record downstream. Intake never
    /// advances acknowledgement itself; it observes the recorded requirement.
    pub acked: bool,
    /// Stable identity derived from the normalized input (see
    /// [`stable_event_id_for`]).
    pub stable_event_identity: EventId,
    /// Full normalized envelope for the intake equality and digest checks.
    pub envelope: NormalizedHostEventEnvelope,
    /// Sealed normalization receipt; must equal `envelope.normalization`.
    pub receipt: HostEventNormalizationReceipt,
}

impl CommittedHostEventIntake {
    /// Builds the intake view for one envelope known committed by the durable
    /// journal. Rejects a receipt that is not the envelope's sealed receipt
    /// and an output digest that does not recompute; extracts every preserved
    /// fact from the envelope instead of re-deriving it.
    pub fn from_envelope(
        envelope: &NormalizedHostEventEnvelope,
        acked: bool,
    ) -> Result<Self, ContractError> {
        let receipt = envelope.normalization.clone();
        let computed = envelope
            .compute_digest()
            .map_err(|_| ContractError::DigestMismatch)?;
        if computed != receipt.output_digest {
            return Err(ContractError::DigestMismatch);
        }
        let (runtime_generation, state_fence) = match &envelope.lineage {
            ProviderObservationLineage::SessionObservation(_) => (None, None),
            ProviderObservationLineage::ExecutionUnitObservation(observation) => (
                Some(observation.binding.runtime_generation),
                Some(observation.binding.state_fence.clone()),
            ),
        };
        let stable_event_identity = stable_event_id_for(
            &envelope.producer_adapter_identity,
            &envelope.adapter_contract_version,
            &envelope.lineage,
            envelope.sequence,
            &envelope.payload,
            &envelope.raw_source.digest,
        )?;
        Ok(Self {
            event_id: envelope.event_id.clone(),
            cursor: envelope.cursor.clone(),
            sequence: envelope.sequence,
            runtime_generation,
            state_fence,
            causal_predecessors: envelope.causal_predecessors.clone(),
            payload_type: envelope.payload.payload_type_tag().to_owned(),
            delivery: envelope.delivery,
            acked,
            stable_event_identity,
            envelope: envelope.clone(),
            receipt,
        })
    }

    /// Re-verifies the preserved facts against the carried envelope: receipt
    /// equality, recomputed output digest, identity/sequence/cursor agreement,
    /// predecessor/delivery/payload-kind agreement, generation/fence presence
    /// agreement with the lineage, and stable-identity recomputation. The
    /// coordinator intake calls this before observing; a view that drifted
    /// from its envelope fails closed here.
    pub fn verify(&self) -> Result<(), ContractError> {
        if self.receipt != self.envelope.normalization {
            return Err(ContractError::DigestMismatch);
        }
        let computed = self
            .envelope
            .compute_digest()
            .map_err(|_| ContractError::DigestMismatch)?;
        if computed != self.receipt.output_digest {
            return Err(ContractError::DigestMismatch);
        }
        if self.event_id != self.envelope.event_id
            || self.cursor != self.envelope.cursor
            || self.sequence != self.envelope.sequence
            || self.causal_predecessors != self.envelope.causal_predecessors
            || self.delivery != self.envelope.delivery
            || self.payload_type != self.envelope.payload.payload_type_tag()
        {
            return Err(ContractError::BindingMismatch);
        }
        let (generation, fence) = match &self.envelope.lineage {
            ProviderObservationLineage::SessionObservation(_) => (None, None),
            ProviderObservationLineage::ExecutionUnitObservation(observation) => (
                Some(&observation.binding.runtime_generation),
                Some(&observation.binding.state_fence),
            ),
        };
        if self.runtime_generation.as_ref() != generation || self.state_fence.as_ref() != fence {
            return Err(ContractError::BindingMismatch);
        }
        let stable = stable_event_id_for(
            &self.envelope.producer_adapter_identity,
            &self.envelope.adapter_contract_version,
            &self.envelope.lineage,
            self.envelope.sequence,
            &self.envelope.payload,
            &self.envelope.raw_source.digest,
        )?;
        if stable != self.stable_event_identity {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }
}
