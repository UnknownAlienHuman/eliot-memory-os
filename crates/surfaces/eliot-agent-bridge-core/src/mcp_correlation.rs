//! MCP invocation correlation vocabulary and derivation (#2899).
//!
//! This module lives in the event owner rather than in a stdio facade for one
//! measured reason: the join that consumes this vocabulary needs the owner's
//! own live journal, and the owner is the only place that holds one. Keeping
//! the vocabulary here is what lets a later host event actually join an
//! earlier emission instead of leaving the whole correlation as unreachable
//! definitions.
//!
//! GitHub issue #7 observed one completed local MCP stdio response while the
//! host later displayed a timeout/stale responding state. The 2026-08-05
//! observation is stale evidence: it does not distinguish a Desktop UI defect,
//! host bridge correlation loss, stdio delivery loss, adapter event loss, or an
//! operation that was never durably staged. This module carries the ELIOT-side
//! half of that correlation — MCP request identity through server handling,
//! response framing, and stdout write/flush disposition — so a fresh
//! current-fingerprint run can bind or refute each hypothesis with evidence.
//!
//! Issue #2899 keeps three facts separate throughout:
//!
//! 1. ELIOT wrote and flushed a response frame ([`EliotEmissionObservation`]);
//! 2. host/UI completion is not yet observed or coverage is unavailable
//!    ([`PartialObservation`], [`CoverageProof`]);
//! 3. competent host evidence proves a route fault, timeout, misclassification
//!    or transport loss ([`CorrelationAssessmentState`], [`RouteDegradation`]).
//!
//! The immediate stdio boundary records only the first fact plus an explicit
//! `PartialUnknown` denominator. It never classifies a healthy emission as
//! degradation and never prescribes recovery without owner evidence. Observed
//! host terminal state ([`HostTerminalState`]) arrives only through the
//! host-event adapter; derived fault classes arrive only through
//! [`assess_correlation`] with competent evidence; retry authority arrives only
//! through an owner-minted [`OwnerValidatedOperationBinding`].
//!
//! Carriers only: nothing here changes wire payloads, canonical write
//! semantics, finish semantics, or host UI expectations. Structured events
//! carry identifiers, digests, stages, counts, and outcome classes; they never
//! carry tool payloads, host secrets, or private conversation content, per
//! `docs/integrations/claude/CLAUDE_INTEGRATION_SECURITY.md`.

use serde::{Deserialize, Serialize};

use crate::TransportEdgeKind;

/// Stable schema identity for ELIOT-side MCP invocation correlation records.
///
/// Version 2 separates the immutable emission observation from later host
/// assessment revisions (issue #2899). Version 1 combined them and classified
/// every healthy emission as route degradation.
pub const CORRELATION_SCHEMA_ID: &str = "eliot.mcp-stdio-correlation.v2";

/// Version of the logical correlation identity bound into every record.
///
/// Version 2 adds the owner-issued request commitment to the digest
/// (issue #2899, W1.2). Version 1 digested the retry identity and effect class
/// but not the commitment the owner actually admitted the request under, so two
/// different admitted requests sharing one retry identity produced one join key.
pub const CORRELATION_IDENTITY_VERSION: u32 = 2;

/// Maximum assessment revisions retained on one correlation record.
///
/// The record is per-invocation and dropped after emission; the cap only
/// bounds the append-only revision chain, never a process-wide table.
pub const MAX_ASSESSMENT_REVISIONS: usize = 16;

/// Maximum missing-evidence entries carried by one assessment summary.
pub const MAX_SUMMARY_EVIDENCE: usize = 8;

/// Maximum actions in one recovery directive.
///
/// Structural, not advisory: a directive is built from exactly two optional
/// steps — one canonical, one host-facing — plus the mandatory escalation tail
/// (see [`RecoveryPlan`]), so the sequence cannot reach a fourth action. The
/// canonical slot holds either reconciliation or replay but never both, because
/// [`CanonicalRecoveryRule`] derives at most one of them.
pub const MAX_RECOVERY_ACTIONS: usize = 3;

/// Lowercase hex SHA-256 over opaque bytes, for join digests.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Versioned logical identity of one MCP invocation (issue #2899, item 1).
///
/// Binds the transport request, the exact method/tool, the serving host
/// profile and session, and the route/process generation. Where the tool
/// owner issued an operation handle, the binding joins it here; raw caller
/// strings never enter this identity until the owner resolves them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CorrelationIdentity {
    /// Identity schema version ([`CORRELATION_IDENTITY_VERSION`]).
    pub version: u32,
    /// Stringified JSON-RPC request id (transport correlation).
    pub mcp_request_id: String,
    /// JSON-RPC method name.
    pub method: String,
    /// Tool name for `tools/call`, when present.
    pub tool_name: Option<String>,
    /// Integration/host access profile that served the request, when observed.
    pub host_profile: Option<String>,
    /// Authenticated ELIOT session that served the request, when known.
    pub session_id: Option<String>,
    /// Runtime instance identity, when observed.
    pub runtime_id: Option<String>,
    /// Authority generation of the serving route/process, when observed.
    pub auth_generation: Option<String>,
    /// Owner-issued request commitment, when the tool owner admitted one.
    ///
    /// The digest of the canonical operation/request the owner admitted, taken
    /// from the owner's own binding (I5.27 `canonical_request_hash`). This is
    /// the *commitment*, not the retry identity: the retry identity says which
    /// name a replay may reuse, while this says which exact admitted request
    /// this correlation is. Both are owner-issued; neither is ever derived from
    /// caller text, so both stay absent while no tool owner mints a binding.
    pub owner_request_commitment: Option<String>,
    /// Owner-issued retry-stable operation handle, when the tool owner bound one.
    pub owner_operation_handle: Option<String>,
    /// Owner-attested effect class, when the tool owner bound one.
    pub effect_class: Option<OperationEffectClass>,
    /// Digest over the canonical identity fields above; the exact join key.
    pub identity_digest: String,
}

/// Explicit observed inputs to one [`CorrelationIdentity`] assembly.
///
/// The identity is assembled from named fields rather than from any caller's
/// record struct, so the owner of this vocabulary never depends on a
/// particular producer's state machine and cannot accidentally absorb a field
/// the producer did not actually observe. Every field is a fact the producing
/// boundary measured; absence stays absence.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorrelationIdentityParts {
    /// Stringified JSON-RPC request id observed by the producer.
    pub mcp_request_id: String,
    /// JSON-RPC method name observed by the producer.
    pub method: String,
    /// Tool name for `tools/call`, when the producer observed one.
    pub tool_name: Option<String>,
    /// Integration/host access profile the producer observed.
    pub host_profile: Option<String>,
    /// Authenticated ELIOT session the producer observed.
    pub session_id: Option<String>,
    /// Runtime instance identity the producer observed.
    pub runtime_id: Option<String>,
    /// Authority generation of the serving route the producer observed.
    pub auth_generation: Option<String>,
    /// Owner-validated operation binding, when a tool owner minted one.
    pub operation_binding: Option<OwnerValidatedOperationBinding>,
}

impl CorrelationIdentity {
    /// Assembles the identity from observed parts and digests it.
    ///
    /// Absent fields digest as empty segments; absence is explicit, never a
    /// fabricated default generation or profile. The digest is over the exact
    /// canonical segment sequence, so the same observed facts always produce
    /// the same join key and any changed fact produces a different one.
    #[must_use]
    pub fn assemble(parts: &CorrelationIdentityParts) -> Self {
        let binding = parts.operation_binding.as_ref();
        let owner_request_commitment = binding.map(|bound| bound.operation_digest.clone());
        let owner_operation_handle = binding.map(|bound| bound.retry_identity.clone());
        let effect_class = binding.map(|bound| bound.effect_class);
        let mut canonical = String::from("eliot.mcp-correlation-identity.v2\0");
        for segment in [
            parts.mcp_request_id.as_str(),
            parts.method.as_str(),
            parts.tool_name.as_deref().unwrap_or_default(),
            parts.host_profile.as_deref().unwrap_or_default(),
            parts.session_id.as_deref().unwrap_or_default(),
            parts.runtime_id.as_deref().unwrap_or_default(),
            parts.auth_generation.as_deref().unwrap_or_default(),
            owner_request_commitment.as_deref().unwrap_or_default(),
            owner_operation_handle.as_deref().unwrap_or_default(),
            effect_class.map_or("", OperationEffectClass::as_str),
        ] {
            canonical.push_str(segment);
            canonical.push('\0');
        }
        Self {
            version: CORRELATION_IDENTITY_VERSION,
            mcp_request_id: parts.mcp_request_id.clone(),
            method: parts.method.clone(),
            tool_name: parts.tool_name.clone(),
            host_profile: parts.host_profile.clone(),
            session_id: parts.session_id.clone(),
            runtime_id: parts.runtime_id.clone(),
            auth_generation: parts.auth_generation.clone(),
            owner_request_commitment,
            owner_operation_handle,
            effect_class,
            identity_digest: sha256_hex(canonical.as_bytes()),
        }
    }
}

/// Identity of the idempotent operation a `tools/call` request carries, if any.
///
/// Extracted read-only from call arguments (`write_id`, `idempotency_key`).
/// These are UNTRUSTED caller hints: they are preserved as a diagnostic
/// carrier only and can never authorize resubmission. Retry authority
/// requires an owner-minted [`OwnerValidatedOperationBinding`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationIdentity {
    /// Caller-supplied idempotency key hint, when the call carried one.
    pub idempotency_key: Option<String>,
    /// Caller-supplied write id hint, when the call carried one.
    pub write_id: Option<String>,
}

impl OperationIdentity {
    /// Records operation identity hints exactly as the producing boundary read
    /// them, unvalidated.
    ///
    /// Validation stays with the owning tool handler; this only preserves the
    /// carrier so a later stage can bind request to operation once the owner
    /// resolves the hints. The hints are untrusted caller text and can never
    /// authorize resubmission on their own: retry authority requires an
    /// owner-minted [`OwnerValidatedOperationBinding`].
    #[must_use]
    pub const fn from_hints(idempotency_key: Option<String>, write_id: Option<String>) -> Self {
        Self {
            idempotency_key,
            write_id,
        }
    }

    /// Whether the call carried any operation identity hint at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.idempotency_key.is_none() && self.write_id.is_none()
    }
}

/// Observable ELIOT-side stage of one MCP invocation.
///
/// Constructed, written, flushed, host-acknowledged, UI-observed, and
/// canonically committed stages stay distinct: reaching one stage never
/// implies a later one (I7.2 transport acknowledgement cannot impersonate
/// durable or canonical application).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationStage {
    /// Raw JSON-RPC line received and parsed.
    Received,
    /// Handler produced a result or typed error; response envelope built.
    HandlerCompleted,
    /// Response bytes framed for stdout emission.
    Framed,
    /// Bytes written and flushed on stdout.
    Emitted,
    /// Stdout emission failed; host delivery is unconfirmed.
    EmissionFailed,
}

impl CorrelationStage {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::HandlerCompleted => "handler_completed",
            Self::Framed => "framed",
            Self::Emitted => "emitted",
            Self::EmissionFailed => "emission_failed",
        }
    }
}

/// Typed outcome of the request handler on this path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerOutcome {
    /// Handler produced a success result.
    CompletedOk,
    /// Handler produced a typed JSON-RPC error envelope with this code.
    JsonRpcError {
        /// JSON-RPC error code of the produced envelope.
        code: i64,
    },
    /// Handler failed without a typed envelope.
    InternalFailure,
    /// No handler ran on this path (relayed responses observe framing only).
    NotObservedOnThisPath,
}

impl HandlerOutcome {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompletedOk => "completed_ok",
            Self::JsonRpcError { .. } => "json_rpc_error",
            Self::InternalFailure => "internal_failure",
            Self::NotObservedOnThisPath => "not_observed_on_this_path",
        }
    }

    /// Whether the handler provably produced a success envelope.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::CompletedOk)
    }
}

/// Terminal cause of one stdout frame emission on the Governor stdio path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmissionCause {
    /// Bytes written and flushed; host delivery handed to the pipe.
    Emitted,
    /// Framed bytes were not fully written.
    WriteFailed,
    /// Bytes were written but the flush failed, so delivery is unconfirmed.
    FlushFailed,
}

impl EmissionCause {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emitted => "emitted",
            Self::WriteFailed => "write_failed",
            Self::FlushFailed => "flush_failed",
        }
    }
}

/// Immutable disposition of one stdout response emission.
///
/// Populated at the exact write/flush stage with the real framed byte count
/// and the real flush outcome. `bytes` counts only fully placed frames; a
/// failed emission carries zero bytes even if the transport accepted a prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StdioEmissionReceipt {
    /// Exact bytes placed on stdout, including the framing newline.
    pub bytes: usize,
    /// Whether the stream flush succeeded after the bytes were written.
    pub flushed: bool,
    /// Terminal cause of this emission.
    pub cause: EmissionCause,
}

/// Immutable ELIOT-side observation of one MCP invocation (issue #2899, item 2).
///
/// Records only what the stdio boundary directly observed: the correlation
/// identity, the receive/handler/frame/emission stages, the exact byte/flush
/// receipt, the typed handler outcome, and the explicit `PartialUnknown`
/// coverage ceiling. A successful emission observation carries no
/// route-degradation code and no recovery directive; those arrive only in
/// later [`Assessment`] revisions derived from competent host evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EliotEmissionObservation {
    /// Versioned logical identity of the invocation.
    pub identity: CorrelationIdentity,
    /// Latest ELIOT-side stage actually reached.
    pub stage: CorrelationStage,
    /// Typed handler outcome observed on this path.
    pub handler_outcome: HandlerOutcome,
    /// Exact framed response bytes, once framed.
    pub framed_bytes: Option<usize>,
    /// Stdout emission disposition, once emitted or failed.
    pub emission: Option<StdioEmissionReceipt>,
    /// Explicit coverage ceiling: host/UI state stays unobserved here.
    pub coverage: PartialObservation,
}

impl EliotEmissionObservation {
    /// Freezes the ELIOT-side record into its immutable observation.
    ///
    /// Takes the observed parts explicitly so this owner never depends on a
    /// producer's state machine. The coverage ceiling is always the honest
    /// stdio-boundary one: no producer can widen it by asserting more.
    #[must_use]
    pub fn observe(
        identity: CorrelationIdentity,
        stage: CorrelationStage,
        handler_outcome: HandlerOutcome,
        framed_bytes: Option<usize>,
        emission: Option<StdioEmissionReceipt>,
    ) -> Self {
        Self {
            identity,
            stage,
            handler_outcome,
            framed_bytes,
            emission,
            coverage: PartialObservation::stdio_boundary(),
        }
    }

    /// Whether ELIOT provably wrote and flushed exactly one response frame.
    pub const fn emitted_exactly_once(&self) -> bool {
        matches!(self.stage, CorrelationStage::Emitted)
    }
}

/// Host/UI terminal state attested by competent host evidence.
///
/// Terminal states a host event can directly attest are `Observed`; stuck,
/// misclassified, and transport-loss classes are never observed — they are
/// derived by [`assess_correlation`] from deadline plus coverage proof, from
/// comparing a host error against a proven success envelope, or from an
/// owner-recorded disconnect edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostTerminalObservation {
    /// A competent host observation attested the terminal state.
    Observed {
        /// What the host terminally reached.
        state: HostTerminalState,
        /// Typed identity/digest evidence for the attesting event.
        evidence: Box<HostObservationEvidence>,
    },
    /// Host/UI terminal state is not observable from this boundary.
    PartialUnknown(PartialObservation),
}

impl HostTerminalObservation {
    /// Stable wire name for structured events.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Observed { .. } => "observed",
            Self::PartialUnknown(_) => "partial_unknown",
        }
    }
}

/// Terminal states a host invocation event can directly attest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostTerminalState {
    /// The host completed the invocation and cleared the responding indicator.
    InvocationCompleted,
    /// The host surfaced an invocation error.
    InvocationError,
}

impl HostTerminalState {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvocationCompleted => "invocation_completed",
            Self::InvocationError => "invocation_error",
        }
    }
}

/// Typed identity/digest evidence for one observed host terminal event.
///
/// Identifiers, digests, sequences, and closed codes only. No tool arguments,
/// response bodies, conversation content, credentials, or host-controlled
/// prose ever enter this evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostObservationEvidence {
    /// Host integration identity that produced the observation.
    pub integration_id: String,
    /// Installation identity the observation is bound to.
    pub installation_id: String,
    /// Session generation the observation is bound to.
    pub session_generation: String,
    /// Process generation the observation is bound to.
    pub process_generation: String,
    /// Owner-attested correlation digest this event is joined to.
    pub correlation_digest: String,
    /// Digest of the route fingerprint the event arrived on.
    pub route_digest: String,
    /// Host event identity from the owning journal.
    pub event_id: String,
    /// Host observation sequence of the event.
    pub sequence: u64,
    /// Resume cursor carried by the event.
    pub cursor: String,
    /// Digest over the canonical event bytes, for replay/conflict checks.
    pub event_digest: String,
    /// Host-observed time carried by the event.
    pub observed_at: String,
    /// Applicable observation deadline, when the owner admitted one.
    pub deadline_unix_ms: Option<u64>,
}

/// Explicit coverage ceiling for unobservable host/UI state.
///
/// `coverage_note` is a closed enum, not free text (issue #2899, W12.2). A
/// `String` here is the one field on this disclosure surface able to carry
/// host-controlled prose: the owner's own `stale_ui_disposition` slot preserves
/// the Desktop/CLI display verbatim, and with a `String` note it could reach an
/// assessment record by assignment. Naming the closed reason instead of writing
/// it removes that path rather than trusting callers to avoid it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartialObservation {
    /// Which host/UI evidence is missing.
    pub missing: Vec<CoverageGap>,
    /// Closed reason the gap cannot be closed from this boundary.
    pub coverage_note: CoverageNote,
}

/// Why a coverage gap cannot be closed from the observing boundary.
///
/// Closed on purpose: the honest reasons are finite and each is a fact about
/// the observing boundary, never a sentence about what the host displayed. No
/// host-authored, model-authored or operator-authored text is representable,
/// so a coverage note cannot become a channel for disclosure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageNote {
    /// Host/UI terminal state lives outside the ELIOT process; it must be
    /// observed out of band through the owner's admitted host-event route.
    #[default]
    HostStateOutsideProcess,
}

impl CoverageNote {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostStateOutsideProcess => "host_state_outside_process",
        }
    }
}

impl std::fmt::Display for CoverageNote {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl PartialObservation {
    /// Coverage ceiling honest at the stdio facade boundary.
    pub fn stdio_boundary() -> Self {
        Self {
            missing: vec![
                CoverageGap::HostBridgeEvents,
                CoverageGap::UiTerminalState,
                CoverageGap::SequenceCursor,
                CoverageGap::EventTimestamps,
            ],
            coverage_note: CoverageNote::HostStateOutsideProcess,
        }
    }
}

/// One unobservable host/UI evidence class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGap {
    /// Host bridge/tool-invocation completion events.
    HostBridgeEvents,
    /// Desktop-visible terminal indicator state.
    UiTerminalState,
    /// Host event sequence/cursor denominator.
    SequenceCursor,
    /// Host-side event timestamps.
    EventTimestamps,
}

impl CoverageGap {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostBridgeEvents => "host_bridge_events",
            Self::UiTerminalState => "ui_terminal_state",
            Self::SequenceCursor => "sequence_cursor",
            Self::EventTimestamps => "event_timestamps",
        }
    }
}

/// Owner-proven coverage over the host-event interval (issue #2899, item 7).
///
/// A stuck/timeout conclusion requires [`CoverageProof::CompleteInterval`]
/// past the admitted deadline. No event yet is pending; a cursor gap is
/// unknown; only an explicit host state or an owner-proven complete interval
/// past deadline may establish a fault class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageProof {
    /// No host event observed yet; the invocation is still pending.
    NoEventYet,
    /// The owner observed a cursor/sequence gap over the interval.
    CursorGap {
        /// Highest contiguous sequence observed.
        last_contiguous_seq: u64,
        /// Highest sequence observed past the gap.
        highest_observed_seq: u64,
    },
    /// The owner proved a contiguous observed interval.
    CompleteInterval {
        /// First contiguous sequence of the proven interval.
        from_seq: u64,
        /// Last contiguous sequence of the proven interval.
        to_seq: u64,
    },
    /// Coverage cannot be proven (rotation, unattached owner, no denominator).
    Indeterminate {
        /// Why coverage is unprovable.
        cause: CoverageIndeterminacy,
    },
}

impl CoverageProof {
    /// Stable wire name for structured events.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoEventYet => "no_event_yet",
            Self::CursorGap { .. } => "cursor_gap",
            Self::CompleteInterval { .. } => "complete_interval",
            Self::Indeterminate { .. } => "indeterminate",
        }
    }
}

/// Why host-event coverage is unprovable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageIndeterminacy {
    /// The owning journal rotated, so the interval is no longer contiguous.
    JournalRotated,
    /// The event owner is unattached, so no denominator exists.
    OwnerUnattached,
    /// No host-event stream was ever admitted for this route.
    NoStreamAdmitted,
    /// The owner's proven interval does not reach this correlation's own
    /// observation point. Contiguity over a disjoint sequence range proves
    /// nothing about an invocation it never covered (issue #2899, item 7:
    /// only an owner-proven complete interval *for this correlation* past the
    /// deadline may establish the fault class). Missing host coverage is
    /// `UNKNOWN`, never a self-reported clean interval.
    CorrelationIntervalNotObserved {
        /// Last sequence the owner's proven interval actually covers.
        last_proven_seq: u64,
        /// Sequence the correlation needs observed for coverage to bind.
        required_seq: u64,
    },
}

impl CoverageIndeterminacy {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JournalRotated => "journal_rotated",
            Self::OwnerUnattached => "owner_unattached",
            Self::NoStreamAdmitted => "no_stream_admitted",
            Self::CorrelationIntervalNotObserved { .. } => "correlation_interval_not_observed",
        }
    }
}

/// Bounded observation window admitted by the event owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationWindow {
    /// Settlement deadline admitted by the owner, when one exists.
    pub deadline_unix_ms: Option<u64>,
    /// Owner clock at assessment time, when the owner supplied one.
    pub now_unix_ms: Option<u64>,
    /// Owner-proven coverage over the host-event interval.
    pub coverage: CoverageProof,
    /// Host-event sequence this correlation must itself reach for a proven
    /// interval to say anything about it.
    ///
    /// The owner proves contiguity over the whole retained journal, and that
    /// journal is not this invocation's. Without a required sequence the
    /// correlation, a contiguous run of *other* invocations' events past an
    /// already-expired deadline would read as owner-proven complete coverage
    /// and establish `HostRespondingStuckAfterDeadline` for an interval the
    /// owner never observed for this correlation (issue #2899 item 7; I7.23
    /// "a native `completed` status may still map to `UNKNOWN_OUTCOME`").
    /// `None` means the owner admitted no sequence binding for this
    /// correlation, which is itself indeterminacy, never coverage.
    pub required_seq: Option<u64>,
}

impl ObservationWindow {
    /// Window honest at the stdio facade: no host evidence, no deadline.
    pub const fn no_host_evidence() -> Self {
        Self {
            deadline_unix_ms: None,
            now_unix_ms: None,
            coverage: CoverageProof::NoEventYet,
            required_seq: None,
        }
    }

    /// Whether this correlation's own host-event interval was observed.
    ///
    /// A `CompleteInterval` is coverage for this correlation only when the
    /// owner admitted a required sequence and the proven interval actually
    /// reaches it. A contiguous interval that stops short of this
    /// correlation's sequence, or any interval with no admitted sequence
    /// binding at all, is missing coverage — `Indeterminate`, never complete.
    pub const fn covers_this_correlation(&self) -> bool {
        match (&self.coverage, self.required_seq) {
            (CoverageProof::CompleteInterval { to_seq, .. }, Some(required)) => *to_seq >= required,
            _ => false,
        }
    }

    /// Whether a complete observed interval extends past the admitted deadline.
    ///
    /// False unless the owner proved a complete interval *for this
    /// correlation* AND admitted both a deadline and a clock reading past it.
    /// Anything else stays pending: a disjoint interval, an unattributed
    /// sequence, a gap, or an absent clock reading is unknown, not a fault.
    pub const fn complete_interval_past_deadline(&self) -> bool {
        match (
            self.covers_this_correlation(),
            self.deadline_unix_ms,
            self.now_unix_ms,
        ) {
            (true, Some(deadline), Some(now)) => now > deadline,
            _ => false,
        }
    }

    /// Coverage restated as coverage *of this correlation*.
    ///
    /// A proven interval the owner never extended to this correlation's own
    /// required sequence is restated as
    /// [`CoverageIndeterminacy::CorrelationIntervalNotObserved`], which
    /// classifies as `TransportOutcomeUnknown`, not as a fault and not as a
    /// clean pending interval. The other variants are already about this
    /// route and pass through unchanged.
    pub fn bounded_coverage(&self) -> CoverageProof {
        match (&self.coverage, self.required_seq) {
            (CoverageProof::CompleteInterval { to_seq, .. }, Some(required_seq))
                if *to_seq < required_seq =>
            {
                CoverageProof::Indeterminate {
                    cause: CoverageIndeterminacy::CorrelationIntervalNotObserved {
                        last_proven_seq: *to_seq,
                        required_seq,
                    },
                }
            }
            _ => self.coverage.clone(),
        }
    }
}

/// Owner-attested effect class of one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationEffectClass {
    /// The operation performs no mutation.
    ReadOnly,
    /// The operation may mutate and is safe to replay under its retry identity.
    MutatingRetryStable,
    /// The operation may mutate and must never be replayed as the same identity.
    MutatingSingleShot,
}

impl OperationEffectClass {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::MutatingRetryStable => "mutating_retry_stable",
            Self::MutatingSingleShot => "mutating_single_shot",
        }
    }

    /// Whether the same operation identity may be reissued for this class.
    ///
    /// `MutatingSingleShot` is refused unconditionally. The owner's approved
    /// recovery subset is an owner decision about *this* operation, and a
    /// single-shot mutation has no lawful same-identity replay under any
    /// subset: reissuing it is the blind duplicate effect I14.21 forbids. The
    /// refusal is a property of the class, not of the approval, so an owner
    /// that lists resubmission cannot authorize it for a single-shot mutation.
    pub const fn is_replay_under_same_identity(self) -> bool {
        matches!(self, Self::ReadOnly | Self::MutatingRetryStable)
    }
}

/// Typed operation binding minted by the tool handler/result owner.
///
/// This is the only retry authority in correlation: [`RecoveryAction::ResubmitSameOperationIdentity`]
/// is derivable only when a binding exists and its owner-approved recovery
/// options include resubmission. Caller `write_id`/`idempotency_key` strings
/// can never mint this type; only the owning tool can, after proving the
/// operation is retry-stable and safe to reconcile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OwnerValidatedOperationBinding {
    /// Owner-issued request commitment: digest of the canonical
    /// operation/request the owner admitted (I5.27 `canonical_request_hash`).
    ///
    /// The commitment says *which* admitted request this is; the retry
    /// identity below says *which* name a replay may reuse. Both are owner
    /// issued, and this one is what `CorrelationIdentity` digests so two
    /// different admitted requests can never share one join key.
    operation_digest: String,
    /// Owner-issued retry-stable identity for same-operation replay.
    retry_identity: String,
    /// Owner-attested effect class.
    effect_class: OperationEffectClass,
    /// Durable state handle carrying the operation disposition.
    durable_state_ref: String,
    /// Independent readback handle, when the owner holds one.
    readback_ref: Option<String>,
    /// Owner-approved recovery subset; resubmit requires explicit inclusion.
    approved_recovery: Vec<RecoveryAction>,
}

/// Why an owner operation binding was rejected at mint time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerBindingError {
    /// A required identity handle was blank.
    BlankField(&'static str),
}

impl std::fmt::Display for OwnerBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlankField(field) => {
                write!(
                    formatter,
                    "owner operation binding field {field} must not be blank"
                )
            }
        }
    }
}

impl std::error::Error for OwnerBindingError {}

impl OwnerValidatedOperationBinding {
    /// Mints the binding from owner-held evidence. Fails closed on blanks.
    ///
    /// Callable only by the tool handler/result owner: the facade never
    /// invokes this constructor, so no binding exists until an owner proves
    /// retry stability. The binding deliberately has no `Deserialize`
    /// implementation: it is minted, never parsed from untrusted input.
    #[allow(
        dead_code,
        reason = "owner seam: minted only by tool owners; none mint yet so resubmit stays omitted (#2899)"
    )]
    pub fn bind(
        operation_digest: &str,
        retry_identity: &str,
        effect_class: OperationEffectClass,
        durable_state_ref: &str,
        readback_ref: Option<&str>,
        approved_recovery: Vec<RecoveryAction>,
    ) -> Result<Self, OwnerBindingError> {
        for (field, value) in [
            ("operation_digest", operation_digest),
            ("retry_identity", retry_identity),
            ("durable_state_ref", durable_state_ref),
        ] {
            if value.trim().is_empty() {
                return Err(OwnerBindingError::BlankField(field));
            }
        }
        Ok(Self {
            operation_digest: operation_digest.to_owned(),
            retry_identity: retry_identity.to_owned(),
            effect_class,
            durable_state_ref: durable_state_ref.to_owned(),
            readback_ref: readback_ref.map(str::to_owned),
            approved_recovery,
        })
    }

    /// Whether the owner approved this recovery action for the operation.
    pub fn allows(&self, action: RecoveryAction) -> bool {
        self.approved_recovery.contains(&action)
    }

    /// Whether this binding authorizes same-operation replay *now*.
    ///
    /// Two independent conditions, neither implying the other, so neither can
    /// stand in for the other:
    ///
    /// 1. the owner listed resubmission among its approved recovery options;
    /// 2. the owner-attested effect class is one whose operation may be
    ///    reissued under the same identity.
    ///
    /// This is half of the same-operation replay authority and only half: the
    /// other half is the current durable disposition, which is read from
    /// [`CanonicalDisposition`] and is refused outright for every class that
    /// could not be lawfully retried. Callers must gate on
    /// [`CanonicalRecoveryRule::same_operation_replay`], which requires both.
    pub fn approves_same_operation_replay(&self) -> bool {
        self.effect_class.is_replay_under_same_identity()
            && self.allows(RecoveryAction::ResubmitSameOperationIdentity)
    }
}

/// Canonical operation disposition, orthogonal to host completion.
///
/// Host completion never proves a canonical commit and a route fault never
/// erases a valid receipt: this disposition moves only on canonical evidence
/// (receipt plus exact readback), never on host/UI observations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalDisposition {
    /// The request performs no mutation.
    ReadOnly,
    /// The request failed before any mutating stage could execute.
    FailedBeforeStage,
    /// A mutation may have committed; reconciliation is still required.
    PossibleCommit,
    /// Committed with a current receipt plus independent exact readback.
    CommittedWithReadback,
    /// The operation provably rolled back; retry-stable replay may be lawful.
    RolledBack,
    /// Canonical outcome is unknown to the assessing path.
    Unknown,
}

impl CanonicalDisposition {
    /// Stable wire name for structured events.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::FailedBeforeStage => "failed_before_stage",
            Self::PossibleCommit => "possible_commit",
            Self::CommittedWithReadback => "committed_with_readback",
            Self::RolledBack => "rolled_back",
            Self::Unknown => "unknown",
        }
    }

    /// The typed recovery rule this class imposes on every derivation.
    ///
    /// This is the whole of A7: each disposition class carries its own rule
    /// rather than being folded into a shared recovery list. The rule is a
    /// property of the canonical class alone — it says what the canonical side
    /// permits — and it is composed with the *cause* by [`derive_recovery`],
    /// which is where the two axes meet.
    ///
    /// [`Self::Unknown`] deliberately shares [`Self::PossibleCommit`]'s rule
    /// rather than earning one of its own: an unknown outcome has no canonical
    /// evidence, so it is exactly as unresolved as a possible commit and is
    /// reconciled the same way. I14.21 — "if unknown → pause Ordering Scope,
    /// preserve operation and open Problem State" — makes that explicit, and a
    /// rule of its own would let an unknown outcome drift toward a retry it has
    /// not earned.
    pub const fn recovery_rule(&self) -> CanonicalRecoveryRule {
        match self {
            Self::ReadOnly => CanonicalRecoveryRule::NoMutationExists,
            Self::FailedBeforeStage => CanonicalRecoveryRule::NothingWasStaged,
            Self::PossibleCommit | Self::Unknown => CanonicalRecoveryRule::ReconcileFirst,
            Self::CommittedWithReadback => CanonicalRecoveryRule::CommitSettled,
            Self::RolledBack => CanonicalRecoveryRule::RolledBackReplayable,
        }
    }

    /// Derives the disposition provable from facade evidence alone.
    ///
    /// Early rejection failed before any handler ran. A current canonical
    /// receipt without readback is a possible commit. Facade-owned protocol
    /// methods are known reads. Anything else stays unknown: the facade must
    /// not claim a tool call was read-only merely because it lacks a receipt.
    ///
    /// This path provably cannot return two of the six classes, and both gaps
    /// are the safe direction rather than an omission:
    ///
    /// - [`Self::CommittedWithReadback`] needs [`CommitEvidence::is_committed`],
    ///   i.e. a current receipt *and* `exact_readback_match == Some(true)`. The
    ///   facade never observes readback, so it passes `None` and the class
    ///   stays with the canonical owner (issue #2899 W11.3: committed requires
    ///   the existing current receipt plus exact readback).
    /// - [`Self::RolledBack`] needs canonical-owner knowledge of the durable
    ///   state, which no facade path holds. Absent it, a receipt reads as
    ///   [`Self::PossibleCommit`] and therefore stays reconciling rather than
    ///   being promoted to a lawful retry.
    pub fn from_facade_evidence(
        method: &str,
        failed_before_handler: bool,
        commit: &CommitEvidence,
    ) -> Self {
        if failed_before_handler {
            return Self::FailedBeforeStage;
        }
        if commit.is_committed() {
            return Self::CommittedWithReadback;
        }
        if commit.canonical_receipt_write_id.is_some() {
            return Self::PossibleCommit;
        }
        if matches!(
            method,
            "initialize" | "ping" | "tools/list" | "prompts/list" | "prompts/get"
        ) {
            return Self::ReadOnly;
        }
        Self::Unknown
    }
}

/// One canonical disposition class's typed recovery rule (issue #2899, W10.8).
///
/// Every variant answers the same two questions for its own class and no other:
/// may a read-only status re-observation precede the rest of the sequence, and
/// may the same operation identity be replayed at all. The class decides; the
/// cause decides the host-facing step; [`derive_recovery`] composes the two.
///
/// The five classes of A7 map to five distinct rules and differ in exactly the
/// places the canonical truth differs:
///
/// ```text
/// NoMutationExists    a read performed no mutation: nothing to reconcile,
///                     and I14.21 licenses same-identity retry only on a known
///                     rollback, so nothing may be replayed either;
/// NothingWasStaged    the request failed before any mutating stage ran, so
///                     there is no durable operation at all — not one a binding
///                     could describe and therefore not one a replay could name;
/// ReconcileFirst      canonical outcome unresolved (possible commit, or
///                     unknown): re-observe canonical state before anything
///                     else, and withhold replay until that re-observation
///                     resolves it;
/// CommitSettled       committed with a current receipt plus exact readback:
///                     re-reading settled truth is not recovery, and reissuing a
///                     durable commit is the duplicate effect I14.21 forbids;
/// RolledBackReplayable provably rolled back: this is the one class I14.21
///                     licenses a same-identity retry for, and only from an
///                     owner-approved, retry-stable binding.
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalRecoveryRule {
    /// No mutation exists, so nothing is left to reconcile or to replay.
    NoMutationExists,
    /// Nothing was ever staged, so there is no operation to reconcile or replay.
    NothingWasStaged,
    /// The canonical outcome is unresolved; reconcile read-only first.
    ReconcileFirst,
    /// The commit is settled by receipt plus exact readback; replay is barred.
    CommitSettled,
    /// The operation provably rolled back; owner-approved replay may be lawful.
    RolledBackReplayable,
}

impl CanonicalRecoveryRule {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoMutationExists => "no_mutation_exists",
            Self::NothingWasStaged => "nothing_was_staged",
            Self::ReconcileFirst => "reconcile_first",
            Self::CommitSettled => "commit_settled",
            Self::RolledBackReplayable => "rolled_back_replayable",
        }
    }

    /// Whether read-only canonical status must be re-observed before anything
    /// else in the sequence.
    ///
    /// True only for [`Self::ReconcileFirst`]. It is the sole positive predicate
    /// for [`RecoveryAction::QueryStatusTool`] in this module, so a status query
    /// can never be derived from a class whose canonical truth is already
    /// decided — and, per W11.3, an unresolved possible commit keeps reconciling
    /// even when the Desktop UI itself timed out.
    pub const fn requires_reconciliation(self) -> bool {
        matches!(self, Self::ReconcileFirst)
    }

    /// The read-only canonical re-observation this class permits, if any.
    pub const fn reconciliation_step(self) -> Option<RecoveryAction> {
        if self.requires_reconciliation() {
            Some(RecoveryAction::QueryStatusTool)
        } else {
            None
        }
    }

    /// Whether this class could ever license a same-operation replay.
    ///
    /// [`Self::RolledBackReplayable`] alone. This is the disposition half of
    /// A6's "current durable disposition": an unresolved, settled or
    /// never-staged class is refused here, before any owner binding is even
    /// consulted, so an approved recovery subset can never lift a class out of
    /// a state in which replay would be unlawful.
    pub const fn permits_same_operation_replay(self) -> bool {
        matches!(self, Self::RolledBackReplayable)
    }

    /// Same-operation replay for this class, from an owner-approved binding.
    ///
    /// Requires both halves of the authority and refuses either one missing:
    /// the disposition must license replay
    /// ([`Self::permits_same_operation_replay`]) and the binding must approve
    /// it ([`OwnerValidatedOperationBinding::approves_same_operation_replay`]).
    /// The class is checked first, so a rolled-back class with no binding and a
    /// binding against a class that cannot be replayed are equally refused.
    pub fn same_operation_replay(
        self,
        binding: Option<&OwnerValidatedOperationBinding>,
    ) -> Option<RecoveryAction> {
        if !self.permits_same_operation_replay() {
            return None;
        }
        binding
            .filter(|binding| binding.approves_same_operation_replay())
            .map(|_| RecoveryAction::ResubmitSameOperationIdentity)
    }
}

/// Evidence gate for calling a candidate committed.
///
/// Committed requires both a current canonical receipt and an independent
/// exact readback. A UI-displayed identifier proves neither.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitEvidence {
    /// Canonical receipt write id resolved independently of any UI, if any.
    pub canonical_receipt_write_id: Option<String>,
    /// Whether independent exact readback reproduced the committed record.
    pub exact_readback_match: Option<bool>,
}

impl CommitEvidence {
    /// True only with a current canonical receipt and exact readback.
    pub const fn is_committed(&self) -> bool {
        self.canonical_receipt_write_id.is_some() && matches!(self.exact_readback_match, Some(true))
    }
}

/// Explicit assessment state of one correlated invocation (issue #2899, item 6).
///
/// Pending, unavailable, gapped, unknown, and local-emission-failed states
/// are not degradation: they prescribe no fault recovery. Route-fault states
/// arise only from competent host evidence or an owner-recorded disconnect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationAssessmentState {
    /// ELIOT emitted exactly once; host observation is still pending.
    EmissionSucceededAwaitingHostObservation,
    /// Host evidence is unavailable or gapped; the outcome stays unknown.
    HostObservationUnavailableOrGapped,
    /// A competent host observation attested invocation completion.
    HostCompleted,
    /// The host surfaced an invocation error consistent with our envelope.
    HostReportedInvocationError,
    /// A complete observed interval passed the deadline with no host terminal.
    HostRespondingStuckAfterDeadline,
    /// The host errored on an envelope ELIOT provably completed successfully.
    ResponseMisclassifiedByHost,
    /// Transport outcome is unknown: coverage is indeterminate after emission.
    TransportOutcomeUnknown,
    /// An owner-recorded disconnect proves transport loss after flush.
    TransportLostAfterFlush,
    /// ELIOT-side emission failed; a local delivery defect, not a host fault.
    EliotEmissionFailed,
}

impl CorrelationAssessmentState {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmissionSucceededAwaitingHostObservation => {
                "emission_succeeded_awaiting_host_observation"
            }
            Self::HostObservationUnavailableOrGapped => "host_observation_unavailable_or_gapped",
            Self::HostCompleted => "host_completed",
            Self::HostReportedInvocationError => "host_reported_invocation_error",
            Self::HostRespondingStuckAfterDeadline => "host_responding_stuck_after_deadline",
            Self::ResponseMisclassifiedByHost => "response_misclassified_by_host",
            Self::TransportOutcomeUnknown => "transport_outcome_unknown",
            Self::TransportLostAfterFlush => "transport_lost_after_flush",
            Self::EliotEmissionFailed => "eliot_emission_failed",
        }
    }

    /// Whether the state is pending (neither completed nor a fault).
    pub const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::EmissionSucceededAwaitingHostObservation
                | Self::HostObservationUnavailableOrGapped
                | Self::TransportOutcomeUnknown
        )
    }

    /// Whether the state attests healthy host completion.
    pub const fn is_completed(self) -> bool {
        matches!(self, Self::HostCompleted)
    }

    /// Whether this state actually carries a route-degradation code.
    ///
    /// Exactly the three states [`assess_correlation`] can build a
    /// [`RouteDegradation`] for. The other six produce `degradation: None`:
    /// a local emission failure is a local fact, a host error consistent with
    /// our own error envelope is correct surfacing, and the pending states are
    /// not faults at all. Counting those as degraded in a disclosure is the
    /// same false-degradation shape issue #2899 exists to remove, so the
    /// summary counts a degraded revision only when this holds.
    pub const fn carries_degradation(self) -> bool {
        matches!(
            self,
            Self::ResponseMisclassifiedByHost
                | Self::TransportLostAfterFlush
                | Self::HostRespondingStuckAfterDeadline
        )
    }
}

/// Typed degradation of the MCP route, derived only from competent evidence.
///
/// This reports route health only. It fabricates neither canonical failure
/// nor canonical success: the canonical operation outcome stays exactly what
/// the committing tool returned. There is deliberately no
/// "emitted-but-unobserved" code: a healthy emission with absent host
/// telemetry is pending coverage, not degradation.
///
/// Closed fields only. There is no free-text `detail`: the record already
/// carries the degradation code, the stage actually reached, and — on the same
/// record — the correlation identity holding the request id, so any detail
/// string would restate those as prose and would be the one place on this
/// surface able to carry host-controlled text (issue #2899, W12.2).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouteDegradation {
    /// Machine-readable degradation class.
    pub code: RouteDegradationCode,
    /// Latest ELIOT-side stage actually reached.
    pub last_observed_stage: CorrelationStage,
}

/// Machine-readable route degradation classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteDegradationCode {
    /// The host observed bytes but misclassified them (timeout/error/stale).
    ResponseMisclassifiedByHost,
    /// The transport was lost after flush; redelivery state is unknown.
    TransportLostAfterFlush,
    /// The host shows no terminal state past the deadline on complete coverage.
    HostRespondingStuckAfterDeadline,
}

impl RouteDegradationCode {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResponseMisclassifiedByHost => "response_misclassified_by_host",
            Self::TransportLostAfterFlush => "transport_lost_after_flush",
            Self::HostRespondingStuckAfterDeadline => "host_responding_stuck_after_deadline",
        }
    }
}

/// Usable recovery directive accompanying a route assessment.
///
/// Bounded and typed: at most [`MAX_RECOVERY_ACTIONS`] actions, no duplicates,
/// and the ordered list is a function of *two* typed inputs — the assessment
/// state and the canonical disposition class — never one shared list applied to
/// every emission (issue #2899, W10.8).
///
/// `canonical_rule` is carried on the directive rather than left implicit, so
/// two classes whose lawful action lists happen to coincide are still distinct
/// plans and are distinguishable as values rather than only in prose. That
/// matters because the coincidence is real: an unresolved commit is the only
/// class that may re-observe canonical state, and a rolled-back operation is
/// the only one that may be reissued, so the other three classes share the
/// host-facing-and-escalate tail and are told apart by the rule that produced
/// it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryDirective {
    /// Ordered recovery actions; later actions apply if earlier ones fail.
    pub actions: Vec<RecoveryAction>,
    /// Canonical disposition rule this sequence was derived under.
    pub canonical_rule: CanonicalRecoveryRule,
    /// Which correlation evidence to attach when escalating.
    pub evidence_hint: String,
}

impl RecoveryDirective {
    /// Comma-joined stable action names for structured events.
    pub fn action_names(&self) -> String {
        self.actions
            .iter()
            .map(|action| action.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Order the disposition's own steps occupy in one cause's sequence.
///
/// Typed per cause rather than shared, because the two causes that recover at
/// all need opposite orders and a common order would be wrong for one of them.
///
/// - [`Self::CanonicalFirst`] settles canonical truth before touching the host.
///   I14.21 — "Kernel queries `WriteReceipt` by idempotency key" — comes before
///   any action that could act on the operation again, and W11.3 requires a
///   possible commit to keep reconciling even when the Desktop UI timed out.
/// - [`Self::TransportFirst`] restores the pipe first, because a read-only
///   status query cannot be issued on a route the owner has proven lost. The
///   canonical steps still follow immediately, never after any host action
///   beyond that one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryOrder {
    /// Disposition steps precede the cause's host-facing step.
    CanonicalFirst,
    /// The cause's single transport step precedes the disposition's steps.
    TransportFirst,
}

/// The two ordered slots a recovery sequence is built from.
///
/// Bounded by construction rather than by a length check applied afterwards:
/// there are two slots plus a mandatory tail, so the plan cannot grow past
/// [`MAX_RECOVERY_ACTIONS`]. Reconciliation and replay share the `canonical`
/// slot because their classes are disjoint — [`CanonicalRecoveryRule`] derives
/// at most one of them — so the two can never both appear.
struct RecoveryPlan {
    /// The one canonical step this class licenses, if any.
    canonical: Option<RecoveryAction>,
    /// The one host-facing step this cause licenses, if any.
    host: Option<RecoveryAction>,
    /// The order those two are emitted in.
    order: RecoveryOrder,
}

impl RecoveryPlan {
    /// Emits the ordered sequence and terminates it in bounded escalation.
    fn into_directive(
        self,
        canonical_rule: CanonicalRecoveryRule,
        identity_digest: &str,
    ) -> RecoveryDirective {
        let Self {
            canonical,
            host,
            order,
        } = self;
        let (first, second) = match order {
            RecoveryOrder::CanonicalFirst => (canonical, host),
            RecoveryOrder::TransportFirst => (host, canonical),
        };
        let mut actions = Vec::with_capacity(MAX_RECOVERY_ACTIONS);
        actions.extend(first);
        actions.extend(second);
        // Every evidenced fault state and the stale-completion case reach here
        // with at least one step, so a proven fault never prescribes nothing.
        // A pending state and a local emission failure never build a plan at
        // all and recover nothing.
        actions.push(RecoveryAction::EscalateWithCorrelationEvidence);
        RecoveryDirective {
            actions,
            canonical_rule,
            evidence_hint: format!("attach {CORRELATION_SCHEMA_ID} record {identity_digest}"),
        }
    }
}

/// One bounded recovery action that never invents canonical outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Restart the stdio route process and replay by operation identity.
    ReconnectStdioRoute,
    /// Refresh the Desktop view; ELIOT-side state is already terminal.
    RefreshDesktopView,
    /// Call a read-only status tool to re-observe canonical state.
    QueryStatusTool,
    /// Resubmit with the same owner-validated identity; never a fresh write id.
    ResubmitSameOperationIdentity,
    /// Escalate with the correlation record attached.
    EscalateWithCorrelationEvidence,
}

impl RecoveryAction {
    /// Stable wire name for structured events.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReconnectStdioRoute => "reconnect_stdio_route",
            Self::RefreshDesktopView => "refresh_desktop_view",
            Self::QueryStatusTool => "query_status_tool",
            Self::ResubmitSameOperationIdentity => "resubmit_same_operation_identity",
            Self::EscalateWithCorrelationEvidence => "escalate_with_correlation_evidence",
        }
    }
}

/// Evidence cited by one assessment revision.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AssessmentEvidence {
    /// Attesting host event evidence, when a host terminal was observed.
    pub host_event: Option<HostObservationEvidence>,
    /// Coverage proof the assessment relied on.
    pub coverage: Option<CoverageProof>,
    /// Owner-recorded transport edge kind, when one decided the assessment.
    pub transport_edge: Option<TransportEdgeKind>,
}

/// Inputs to one correlation assessment.
///
/// Every input is either ELIOT-observed, owner-proven, or explicitly absent.
/// Absent host evidence yields a pending state, never a fault.
pub struct AssessmentInputs<'a> {
    /// Immutable ELIOT-side emission observation.
    pub emission: &'a EliotEmissionObservation,
    /// Competent host terminal observation, or explicit partial-unknown.
    pub host: &'a HostTerminalObservation,
    /// Bounded observation window admitted by the event owner.
    pub window: &'a ObservationWindow,
    /// Owner-recorded transport edge for this invocation, when one exists.
    pub transport_edge: Option<TransportEdgeKind>,
    /// Owner-validated operation binding, when a tool owner minted one.
    pub operation_binding: Option<&'a OwnerValidatedOperationBinding>,
    /// Canonical operation disposition from canonical evidence only.
    pub canonical: &'a CanonicalDisposition,
    /// Whether the owner confirmed a stale UI while the host completed.
    ///
    /// A bare flag on purpose: it is the one input this module cannot verify,
    /// because no owner binding scopes a UI-staleness observation to a single
    /// invocation. The owner's `stale_ui_disposition` slot is a single
    /// unbound value that preserves the Desktop/CLI display verbatim, so
    /// reading it here would attribute one surface snapshot to every
    /// correlation on the route — the same over-attribution that
    /// `CoverageIndeterminacy::CorrelationIntervalNotObserved` exists to
    /// refuse. `true` is therefore a claim only an owner that can bind the
    /// observation to one request identity may make, and no current producer
    /// can, so it stays false on every live path. The consequence is the safe
    /// one: refresh-the-UI is withheld rather than offered speculatively.
    pub ui_confirmed_stale: bool,
}

/// One derived route assessment: explicit state plus bounded recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    /// Explicit assessment state.
    pub state: CorrelationAssessmentState,
    /// Route degradation, present only for competent fault states.
    pub degradation: Option<RouteDegradation>,
    /// Recovery directive, present only when a lawful recovery exists.
    pub recovery: Option<RecoveryDirective>,
    /// Evidence the assessment relied on.
    pub evidence: AssessmentEvidence,
}

/// Derives the route assessment from observed cause plus operation disposition.
///
/// A provably flushed frame is a precondition, not a verdict: emission alone
/// never yields a degradation code or a recovery directive (issue #2899). A
/// record that never reached the pipe is a local fact and stays local — it
/// prescribes no host-facing route recovery. Among emissions that provably
/// reached the pipe, decision order is strongest-evidence-first: an explicit
/// host terminal, then an owner-recorded disconnect, then a complete interval
/// past deadline, then coverage-only pending states. Only those evidenced
/// states derive recovery. Misclassification requires a proven success
/// envelope: a host error against an error envelope (or an unobserved relayed
/// envelope) is consistent surfacing, not a route fault.
pub fn assess_correlation(inputs: &AssessmentInputs<'_>) -> Assessment {
    let emission = inputs.emission;
    let mut evidence = AssessmentEvidence {
        host_event: None,
        coverage: Some(inputs.window.coverage.clone()),
        transport_edge: inputs.transport_edge,
    };
    if !emission.emitted_exactly_once() {
        return Assessment {
            state: CorrelationAssessmentState::EliotEmissionFailed,
            degradation: None,
            recovery: None,
            evidence,
        };
    }
    if let HostTerminalObservation::Observed {
        state,
        evidence: host_evidence,
    } = inputs.host
    {
        evidence.host_event = Some(host_evidence.as_ref().clone());
        return match state {
            HostTerminalState::InvocationCompleted => {
                let state = CorrelationAssessmentState::HostCompleted;
                Assessment {
                    state,
                    degradation: None,
                    recovery: derive_recovery(
                        &emission.identity.identity_digest,
                        state,
                        inputs.operation_binding,
                        inputs.canonical,
                        inputs.ui_confirmed_stale,
                    ),
                    evidence,
                }
            }
            HostTerminalState::InvocationError => assess_host_error(inputs, evidence),
        };
    }
    if matches!(inputs.transport_edge, Some(TransportEdgeKind::Disconnect)) {
        let state = CorrelationAssessmentState::TransportLostAfterFlush;
        return Assessment {
            state,
            degradation: Some(degradation_for(
                emission,
                RouteDegradationCode::TransportLostAfterFlush,
            )),
            recovery: derive_recovery(
                &emission.identity.identity_digest,
                state,
                inputs.operation_binding,
                inputs.canonical,
                inputs.ui_confirmed_stale,
            ),
            evidence,
        };
    }
    if inputs.window.complete_interval_past_deadline() {
        let state = CorrelationAssessmentState::HostRespondingStuckAfterDeadline;
        return Assessment {
            state,
            degradation: Some(degradation_for(
                emission,
                RouteDegradationCode::HostRespondingStuckAfterDeadline,
            )),
            recovery: derive_recovery(
                &emission.identity.identity_digest,
                state,
                inputs.operation_binding,
                inputs.canonical,
                inputs.ui_confirmed_stale,
            ),
            evidence,
        };
    }
    // A contiguous interval that stops short of this correlation's own
    // required sequence proves nothing here: the owner never observed this
    // invocation's host events, so the outcome is UNKNOWN and never a fault
    // (issue #2899 item 7; I7.23 "missing host coverage is TAINTED/UNKNOWN,
    // never a self-reported PASS").
    let coverage = inputs.window.bounded_coverage();
    if coverage != inputs.window.coverage {
        evidence.coverage = Some(coverage.clone());
    }
    let state = match &coverage {
        CoverageProof::CursorGap { .. } => {
            CorrelationAssessmentState::HostObservationUnavailableOrGapped
        }
        CoverageProof::Indeterminate { .. } => CorrelationAssessmentState::TransportOutcomeUnknown,
        CoverageProof::NoEventYet | CoverageProof::CompleteInterval { .. } => {
            CorrelationAssessmentState::EmissionSucceededAwaitingHostObservation
        }
    };
    Assessment {
        state,
        degradation: None,
        recovery: None,
        evidence,
    }
}

/// Assesses a host-reported invocation error against the emitted envelope.
///
/// A host error on an envelope ELIOT provably completed successfully is
/// misclassification. A host error on an error envelope — or on a relayed
/// envelope this path never observed — is consistent surfacing: no route
/// degradation and no route recovery.
fn assess_host_error(inputs: &AssessmentInputs<'_>, evidence: AssessmentEvidence) -> Assessment {
    let emission = inputs.emission;
    if emission.handler_outcome.is_success() {
        let state = CorrelationAssessmentState::ResponseMisclassifiedByHost;
        Assessment {
            state,
            degradation: Some(degradation_for(
                emission,
                RouteDegradationCode::ResponseMisclassifiedByHost,
            )),
            recovery: derive_recovery(
                &emission.identity.identity_digest,
                state,
                inputs.operation_binding,
                inputs.canonical,
                inputs.ui_confirmed_stale,
            ),
            evidence,
        }
    } else {
        Assessment {
            state: CorrelationAssessmentState::HostReportedInvocationError,
            degradation: None,
            recovery: None,
            evidence,
        }
    }
}

/// Builds the degradation record for a competent fault state.
///
/// Called only with fault codes proven by host evidence; there is no
/// emitted-but-unobserved code to construct.
fn degradation_for(
    emission: &EliotEmissionObservation,
    code: RouteDegradationCode,
) -> RouteDegradation {
    RouteDegradation {
        code,
        last_observed_stage: emission.stage,
    }
}

/// Derives typed, bounded recovery from state plus operation disposition.
///
/// Recovery is a function of two typed inputs and never one shared list
/// (issue #2899, W10.8). The *cause* contributes at most one host-facing step
/// and the ordering; the *disposition class* contributes at most one canonical
/// step. The two land in separate slots, so neither can absorb the other and
/// the result is bounded by construction.
///
/// Cause by cause:
///
/// - a pending, unknown or gapped outcome recovers nothing, because nothing
///   has been established about the route;
/// - a healthy completion recovers nothing unless the owner confirmed a stale
///   UI, in which case refreshing the Desktop view is offered and nothing else
///   (W10.3);
/// - a directly observed local emission failure is a local fact and prescribes
///   nothing host-facing;
/// - a host error consistent with the envelope ELIOT produced is correct
///   surfacing and recovers nothing;
/// - a host error on a proven success envelope is a route fault whose only
///   lawful step is whatever the disposition class licenses;
/// - a proven transport loss restores the pipe first, because the canonical
///   status query cannot be issued until it is back, and reconciles or replays
///   immediately after;
/// - a complete observed interval past the deadline settles canonical truth
///   first, then refreshes the view.
///
/// The class step is the same wherever it appears, so a rolled-back
/// retry-stable operation may be reissued under a stuck host exactly as it may
/// under a proven transport loss; the two causes differ only in what precedes
/// it.
///
/// Within every branch the disposition class decides whether canonical status
/// is re-observed before anything else and whether the same operation identity
/// may be replayed; see [`CanonicalRecoveryRule`] for why each of A7's five
/// classes differs, and [`CanonicalRecoveryRule::same_operation_replay`] for
/// the two independent conditions replay requires.
pub fn derive_recovery(
    identity_digest: &str,
    state: CorrelationAssessmentState,
    operation_binding: Option<&OwnerValidatedOperationBinding>,
    canonical: &CanonicalDisposition,
    ui_confirmed_stale: bool,
) -> Option<RecoveryDirective> {
    let rule = canonical.recovery_rule();
    let (canonical_action, host, order) = match state {
        CorrelationAssessmentState::EmissionSucceededAwaitingHostObservation
        | CorrelationAssessmentState::HostObservationUnavailableOrGapped
        | CorrelationAssessmentState::TransportOutcomeUnknown
        | CorrelationAssessmentState::HostReportedInvocationError
        | CorrelationAssessmentState::EliotEmissionFailed => return None,
        // W10.3: a confirmed stale UI beside a host completion is the one case
        // where refreshing the Desktop view is offered on a healthy invocation.
        // Nothing canonical is added here even if the class could license a
        // replay: the host attested this invocation completed, so there is no
        // unresolved outcome to settle and no route action to take, and a
        // healthy completion recovers the view and nothing more.
        CorrelationAssessmentState::HostCompleted => {
            if !ui_confirmed_stale {
                return None;
            }
            (
                None,
                Some(RecoveryAction::RefreshDesktopView),
                RecoveryOrder::CanonicalFirst,
            )
        }
        // The canonical truth is settled or unknown; nothing host-facing is
        // owed for a misclassification, only whatever the class licenses.
        CorrelationAssessmentState::ResponseMisclassifiedByHost => (
            canonical_step(rule, operation_binding),
            None,
            RecoveryOrder::CanonicalFirst,
        ),
        CorrelationAssessmentState::TransportLostAfterFlush => (
            canonical_step(rule, operation_binding),
            Some(RecoveryAction::ReconnectStdioRoute),
            RecoveryOrder::TransportFirst,
        ),
        CorrelationAssessmentState::HostRespondingStuckAfterDeadline => (
            canonical_step(rule, operation_binding),
            Some(RecoveryAction::RefreshDesktopView),
            RecoveryOrder::CanonicalFirst,
        ),
    };
    Some(
        RecoveryPlan {
            canonical: canonical_action,
            host,
            order,
        }
        .into_directive(rule, identity_digest),
    )
}

/// The one canonical step a disposition class licenses, if any.
///
/// Reconciliation and replay are mutually exclusive by class, so this returns
/// at most one action: an unresolved class reconciles and withholds replay, a
/// settled or never-staged class does neither, and only a rolled-back class may
/// replay. Deriving both and then choosing between them at the call site is
/// what produced the previous single-list behaviour, so the exclusion is
/// resolved here instead.
fn canonical_step(
    rule: CanonicalRecoveryRule,
    operation_binding: Option<&OwnerValidatedOperationBinding>,
) -> Option<RecoveryAction> {
    rule.reconciliation_step()
        .or_else(|| rule.same_operation_replay(operation_binding))
}

/// One append-only assessment revision under a logical correlation.
///
/// The immediate emission observation stays immutable; a later host
/// completion or fault appends a linked revision under the same identity
/// digest. Revisions never rewrite history and never leave a false
/// degradation current beside a healthy completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AssessmentRevision {
    /// Identity digest of the logical correlation this revises.
    pub identity_digest: String,
    /// Monotonic revision number, assigned at append.
    pub revision: u32,
    /// Previous revision number this supersedes, when one exists.
    pub supersedes: Option<u32>,
    /// Derived assessment carried by this revision.
    pub assessment: Assessment,
}

/// Bounded append-only log of assessment revisions for one invocation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AssessmentLog {
    /// Identity digest every revision must share, once set.
    identity_digest: Option<String>,
    /// Revisions in append order.
    revisions: Vec<AssessmentRevision>,
}

/// Why an assessment revision append was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssessmentLogError {
    /// The revision belongs to a different logical correlation.
    IdentityMismatch,
    /// The bounded log is full.
    LogFull,
}

impl std::fmt::Display for AssessmentLogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityMismatch => {
                formatter.write_str("assessment revision identity does not match the log")
            }
            Self::LogFull => formatter.write_str("assessment revision log is full"),
        }
    }
}

impl std::error::Error for AssessmentLogError {}

impl AssessmentLog {
    /// Appends one assessment, assigning its revision number. Fails closed.
    ///
    /// Rejects revisions for a different identity digest and refuses to grow
    /// past [`MAX_ASSESSMENT_REVISIONS`]; existing revisions are never
    /// mutated or removed.
    pub fn append(
        &mut self,
        identity_digest: &str,
        assessment: Assessment,
    ) -> Result<&AssessmentRevision, AssessmentLogError> {
        if let Some(held) = &self.identity_digest
            && held != identity_digest
        {
            return Err(AssessmentLogError::IdentityMismatch);
        }
        if self.revisions.len() >= MAX_ASSESSMENT_REVISIONS {
            return Err(AssessmentLogError::LogFull);
        }
        let revision =
            u32::try_from(self.revisions.len()).map_err(|_| AssessmentLogError::LogFull)?;
        let supersedes = revision.checked_sub(1);
        self.identity_digest = Some(identity_digest.to_owned());
        self.revisions.push(AssessmentRevision {
            identity_digest: identity_digest.to_owned(),
            revision,
            supersedes,
            assessment,
        });
        self.revisions.last().ok_or(AssessmentLogError::LogFull)
    }

    /// Revisions in append order.
    pub fn revisions(&self) -> &[AssessmentRevision] {
        &self.revisions
    }

    /// Host evidence this correlation has already accepted, read back from its
    /// own retained revision chain.
    ///
    /// This is the correlation's own record, never a caller assertion: the
    /// bridge join compares a later host event against the evidence recorded
    /// here, so a caller cannot present an empty expected set and have a
    /// correlation close once per event.
    pub fn latest_host_evidence(&self) -> Option<&HostObservationEvidence> {
        self.revisions
            .iter()
            .rev()
            .find_map(|revision| revision.assessment.evidence.host_event.as_ref())
    }

    /// Latest revision, when one exists.
    pub fn latest(&self) -> Option<&AssessmentRevision> {
        self.revisions.last()
    }

    /// The revision that currently holds, and whether it supersedes an earlier
    /// assessment of the same correlation.
    ///
    /// The second half is the whole of W9.3's first clause. `AssessmentLog` is
    /// append-only, so a healthy completion arriving after a degradation cannot
    /// erase the degradation's bytes and must not leave that degradation
    /// reading as current either. The link is therefore reported where the
    /// record is read: `supersedes_earlier` on the current revision is the
    /// positive evidence that this correlation was re-assessed, the earlier
    /// revision stays exactly as written, and
    /// [`AssessmentSummary`] moves its degradation code out of `degraded` and
    /// into the superseded bucket.
    pub fn current(&self) -> Option<RevisionOutcome<'_>> {
        self.revisions.last().map(|revision| RevisionOutcome {
            revision,
            supersedes_earlier: revision.supersedes.is_some(),
        })
    }
}

/// What a correlation currently holds, read out of its append-only chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevisionOutcome<'a> {
    /// The revision that currently holds.
    pub revision: &'a AssessmentRevision,
    /// Whether this revision supersedes an earlier assessment.
    pub supersedes_earlier: bool,
}

impl RevisionOutcome<'_> {
    /// Current state of the correlation.
    pub fn state(&self) -> CorrelationAssessmentState {
        self.revision.assessment.state
    }

    /// Current route degradation, when the current revision carries one.
    pub fn degradation(&self) -> Option<&RouteDegradation> {
        self.revision.assessment.degradation.as_ref()
    }
}

/// Bounded pending/completed/degraded counts plus missing evidence.
///
/// Counts describe the **current** revision of one correlation, not every
/// revision it ever held (issue #2899, W9.3). A degradation that a later
/// assessment superseded is counted under
/// [`Self::superseded_degradations`] with its code named, never under
/// [`Self::degraded`]: reporting it as current is exactly the immutable false
/// degradation sitting beside a healthy completion, and rewriting the earlier
/// revision to remove it would be rewriting historical bytes. Supersession is
/// reported, not erased, so the false assessment stays visible as history.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AssessmentSummary {
    /// Revisions currently in a pending state.
    pub pending: u32,
    /// Revisions currently attesting healthy host completion.
    pub completed: u32,
    /// Revisions currently carrying a route-degradation code.
    ///
    /// Counts only states for which [`CorrelationAssessmentState::carries_degradation`]
    /// holds, so a local emission failure or a consistent host error on our own
    /// error envelope is never counted as a route degradation.
    pub degraded: u32,
    /// Degradation codes present only in superseded revisions.
    pub superseded_degradations: u32,
    /// Bounded names of those superseded degradation codes.
    pub superseded_degradation_codes: Vec<String>,
    /// Bounded exact-missing-evidence tags across the revisions.
    pub missing_evidence: Vec<String>,
}

impl AssessmentSummary {
    /// Summarizes one correlation's append-only chain.
    ///
    /// Takes the chain rather than an arbitrary revision slice so "current" is
    /// decidable: the last revision is current and every earlier one is
    /// superseded by construction, because `AssessmentLog::append` numbers
    /// revisions sequentially and links each to the one before it.
    ///
    /// Missing-evidence tags are collected across the whole chain, bounded by
    /// [`MAX_SUMMARY_EVIDENCE`], and are appended before the superseded codes
    /// so that the bound can never be consumed by history and cost the current
    /// revision its denominator.
    #[must_use]
    pub fn summarize(log: &AssessmentLog) -> Self {
        let revisions = log.revisions();
        let Some((current, superseded)) = revisions.split_last() else {
            return Self::default();
        };
        let mut summary = Self::default();
        for revision in superseded {
            for tag in missing_evidence_tags(revision) {
                push_bounded(&mut summary.missing_evidence, tag);
            }
            if let Some(degradation) = &revision.assessment.degradation {
                summary.superseded_degradations += 1;
                push_bounded(
                    &mut summary.superseded_degradation_codes,
                    degradation.code.as_str().to_owned(),
                );
            }
        }
        for tag in missing_evidence_tags(current) {
            push_bounded(&mut summary.missing_evidence, tag);
        }
        let state = current.assessment.state;
        if state.is_pending() {
            summary.pending += 1;
        } else if state.is_completed() {
            summary.completed += 1;
        }
        if state.carries_degradation() {
            summary.degraded += 1;
        }
        summary
    }
}

/// Appends one bounded disclosure tag, skipping a repeat and stopping at the cap.
fn push_bounded(bucket: &mut Vec<String>, tag: String) {
    if bucket.len() >= MAX_SUMMARY_EVIDENCE {
        return;
    }
    if !bucket.contains(&tag) {
        bucket.push(tag);
    }
}

/// Exact missing evidence for one revision, as stable identifier tags.
fn missing_evidence_tags(revision: &AssessmentRevision) -> Vec<String> {
    let state = revision.assessment.state.as_str().to_owned();
    match revision.assessment.state {
        CorrelationAssessmentState::EmissionSucceededAwaitingHostObservation => {
            vec![format!("{state}:host_terminal_event")]
        }
        CorrelationAssessmentState::HostObservationUnavailableOrGapped => {
            vec![format!("{state}:contiguous_host_interval")]
        }
        CorrelationAssessmentState::TransportOutcomeUnknown => {
            let cause =
                revision
                    .assessment
                    .evidence
                    .coverage
                    .as_ref()
                    .map_or("unknown", |coverage| match coverage {
                        CoverageProof::Indeterminate { cause } => cause.as_str(),
                        CoverageProof::NoEventYet
                        | CoverageProof::CursorGap { .. }
                        | CoverageProof::CompleteInterval { .. } => coverage.as_str(),
                    });
            vec![format!("{state}:coverage_denominator:{cause}")]
        }
        CorrelationAssessmentState::HostCompleted
        | CorrelationAssessmentState::HostReportedInvocationError
        | CorrelationAssessmentState::HostRespondingStuckAfterDeadline
        | CorrelationAssessmentState::ResponseMisclassifiedByHost
        | CorrelationAssessmentState::TransportLostAfterFlush
        | CorrelationAssessmentState::EliotEmissionFailed => Vec::new(),
    }
}
