//! Structured Governor-daemon admission diagnostics (issue #740).
//!
//! # Architecture
//! - **A13.10 Observability and Diagnostic Brief** — diagnostics project
//!   already-admitted evidence; a log is never a canonical receipt.
//! - **A13.2 Kernel and failure domains** — Kernel keeps handshake, fence,
//!   reservation and transition ownership; this module only names the
//!   reporting owner of each record.
//! - **A2.3 Modular architecture** — bounded pure projection cell; no new
//!   runtime, process, or failure boundary.
//!
//! # Implementation
//! - **I1.8 daemon/Kernel ownership and call paths** — every record maps to
//!   the exact daemon boundary that already observed the evidence.
//! - **I2.16 bounded workset** — this file plus the inventoried spans are the
//!   complete #740 daemon partition; Governor/protocol/shared-agent
//!   implementations are never loaded here.
//!
//! This module owns no semantic admission, scheduling, transition, retry,
//! strict-Finish, Store, Kernel, process, or authority behavior. It converts
//! already-validated identities and already-typed owner outcomes into bounded
//! stderr records. Missing identity stays [`UNAVAILABLE`]; secret or
//! payload-bearing input is replaced with [`REDACTED`] before formatting,
//! including nested owner error text.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

use eliot_protocol::{AgentActivationResolutionDisposition, AgentActivationResultAckOutcome};

use super::agent_fabric::{FabricAdmission, FabricError, Reservation};
use super::{DaemonError, PROTOCOL_VERSION, SERVICE_NAME};

/// Marker recorded when an identity was not available from its owner.
/// Missing identity is never synthesized.
pub const UNAVAILABLE: &str = "unavailable";
/// Marker recorded when input carried secret or payload-bearing content.
/// Redaction happens before formatting, never after.
pub const REDACTED: &str = "[redacted]";
/// Maximum identity characters retained in any record.
pub const MAX_IDENTITY_CHARS: usize = 128;
/// Maximum free-text detail characters retained in any record.
pub const MAX_DETAIL_CHARS: usize = 512;
/// Maximum captured bytes retained per thread-local test capture.
pub const MAX_CAPTURE_BYTES: usize = 64 * 1024;
/// Maximum records retained per thread-local test capture.
pub const MAX_CAPTURE_RECORDS: usize = 512;
/// Maximum repeated-failure lines emitted before suppression counts only.
pub const MAX_REPEATED_FAILURE_LINES: u64 = 8;
/// Stable unknown-state code for unresolved results.
pub const STATE_UNKNOWN: &str = "unknown";

/// Substrings that mark secret-bearing input. Any identity or detail
/// containing one of these (case-insensitive) records [`REDACTED`] instead
/// of the value. The list covers credential, token, provider/DB and
/// restricted-handle shapes without ever matching daemon identity formats
/// (`task-1`, `scope:governor`, `epoch:…/gen:…`, `req-…`, `op-…`).
const SECRET_MARKERS: [&str; 18] = [
    "sk-live",
    "sk-test",
    "sk-ant-",
    "sk-proj-",
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "bearer",
    "api-key",
    "apikey",
    "api_key",
    "private-key",
    "privatekey",
    "private_key",
    "connection-string",
    "connectionstring",
];

/// Substrings that mark model text, Context payload, evidence-body or user
/// content. Diagnostics carry identities only, so any value containing one
/// of these (case-insensitive) records [`REDACTED`] instead of the value.
const PAYLOAD_MARKERS: [&str; 7] = [
    "model-text",
    "context-payload",
    "evidence-body",
    "user-content",
    "system-prompt",
    "prompt-bytes",
    "completion-bytes",
];

/// Returns true when the value carries secret or payload-bearing content.
#[must_use]
pub fn carries_denied_content(value: &str) -> bool {
    let lowered = value.to_lowercase();
    SECRET_MARKERS
        .iter()
        .chain(PAYLOAD_MARKERS.iter())
        .any(|marker| lowered.contains(marker))
}

/// Sanitizes one validated identity for a record.
///
/// Empty/whitespace/control-bearing input records [`UNAVAILABLE`] (missing
/// identity is never synthesized). Secret or payload-bearing input records
/// [`REDACTED`] before any other check. Input outside the identity charset
/// (`A-Z a-z 0-9 : . _ / -`) records [`UNAVAILABLE`]. Anything longer than
/// [`MAX_IDENTITY_CHARS`] characters is truncated to the bound.
#[must_use]
pub fn sanitize_identity(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return UNAVAILABLE.to_owned();
    }
    if carries_denied_content(trimmed) {
        return REDACTED.to_owned();
    }
    if !trimmed
        .chars()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, ':' | '.' | '_' | '/' | '-'))
    {
        return UNAVAILABLE.to_owned();
    }
    trimmed.chars().take(MAX_IDENTITY_CHARS).collect()
}

/// Sanitizes one owner-supplied free-text detail for a record.
///
/// Control characters and single quotes become `?` (records stay
/// single-line and single-quoted), secret or payload-bearing text records
/// [`REDACTED`], and anything longer than [`MAX_DETAIL_CHARS`] characters
/// is truncated to the bound.
#[must_use]
pub fn sanitize_detail(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|byte| {
            if byte.is_control() || byte == '\'' {
                '?'
            } else {
                byte
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return UNAVAILABLE.to_owned();
    }
    if carries_denied_content(trimmed) {
        return REDACTED.to_owned();
    }
    trimmed.chars().take(MAX_DETAIL_CHARS).collect()
}

/// Computes the deterministic admission digest over one namespace plus the
/// ordered identity parts (FNV-1a 64, lowercase hex).
///
/// No hash dependency is required: the digest is diagnostic correlation
/// only, never an admission decision input. Identical inputs always produce
/// identical digests; different dispositions or identities change it.
#[must_use]
pub fn admission_digest(namespace: &str, parts: &[&str]) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for byte in namespace
        .as_bytes()
        .iter()
        .chain([&0xff])
        .chain(parts.iter().flat_map(|part| part.as_bytes()))
        .chain([&0xfe])
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

// ---------------------------------------------------------------------------
// Subscriber lifecycle (binary startup) and scoped test capture
// ---------------------------------------------------------------------------

/// Outcome of [`init_daemon_diagnostics`]. Re-initialization never replaces
/// the installed subscriber: the first owner keeps ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriberInit {
    /// This call installed the bounded stderr subscriber.
    Initialized,
    /// A subscriber was already installed; it is left untouched.
    AlreadyInitialized,
}

static SUBSCRIBER_INIT: OnceLock<SubscriberInit> = OnceLock::new();

/// Initializes the one bounded daemon diagnostics subscriber.
///
/// The subscriber writes structured records to stderr only; protocol/status
/// stdout bytes and framing are never touched. The only failure mode is an
/// already-installed global subscriber, which maps to
/// [`SubscriberInit::AlreadyInitialized`] — ownership is preserved, there is
/// no panic, no recursive logging, and no fabricated success. Reusable
/// daemon/composition construction never calls this; only binary startup
/// does.
#[must_use]
pub fn init_daemon_diagnostics() -> SubscriberInit {
    *SUBSCRIBER_INIT.get_or_init(|| {
        match tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_target(true)
            .try_init()
        {
            Ok(()) => SubscriberInit::Initialized,
            Err(_) => SubscriberInit::AlreadyInitialized,
        }
    })
}

thread_local! {
    static CAPTURE_SLOTS: RefCell<Option<Rc<RefCell<CaptureState>>>> =
        const { RefCell::new(None) };
}

#[derive(Debug, Default)]
struct CaptureState {
    lines: Vec<String>,
    bytes: usize,
    dropped: u64,
}

/// Scoped guard installing a bounded thread-local capture.
///
/// While installed, every [`emit_line`] record is appended to this thread's
/// capture in addition to the `tracing` event. Captures are thread-local so
/// parallel tests never contaminate each other. Dropping the guard restores
/// the previous capture (usually none).
pub struct CaptureGuard {
    previous: Option<Rc<RefCell<CaptureState>>>,
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        CAPTURE_SLOTS.with(|slots| {
            if let Ok(mut slots) = slots.try_borrow_mut() {
                slots.clone_from(&self.previous);
            }
        });
    }
}

/// Installs a bounded thread-local capture and returns its guard.
#[must_use]
pub fn install_capture() -> CaptureGuard {
    let previous = CAPTURE_SLOTS.with(|slots| {
        if let Ok(mut slots) = slots.try_borrow_mut() {
            let previous = slots.clone();
            *slots = Some(Rc::new(RefCell::new(CaptureState::default())));
            Some(previous)
        } else {
            None
        }
    });
    CaptureGuard {
        previous: previous.flatten(),
    }
}

/// Returns the lines captured on this thread under the active guard.
#[must_use]
pub fn captured_records() -> Vec<String> {
    CAPTURE_SLOTS.with(|slots| {
        slots
            .try_borrow()
            .map(|slots| {
                slots.as_ref().map_or_else(Vec::new, |state| {
                    state
                        .try_borrow()
                        .map_or_else(|_| Vec::new(), |state| state.lines.clone())
                })
            })
            .unwrap_or_default()
    })
}

/// Returns the overflow-dropped record count for this thread's capture.
#[must_use]
pub fn capture_overflow_dropped() -> u64 {
    CAPTURE_SLOTS.with(|slots| {
        if let Ok(slots) = slots.try_borrow() {
            slots.as_ref().map_or(0, |state| {
                state.try_borrow().map_or(0, |state| state.dropped)
            })
        } else {
            0
        }
    })
}

fn push_capture(line: &str) {
    CAPTURE_SLOTS.with(|slots| {
        if let Ok(slots) = slots.try_borrow()
            && let Some(state) = slots.as_ref()
            && let Ok(mut state) = state.try_borrow_mut()
        {
            if state.lines.len() >= MAX_CAPTURE_RECORDS
                || state.bytes.saturating_add(line.len()) > MAX_CAPTURE_BYTES
            {
                state.dropped = state.dropped.saturating_add(1);
                return;
            }
            state.bytes = state.bytes.saturating_add(line.len());
            state.lines.push(line.to_owned());
        }
    });
}

// ---------------------------------------------------------------------------
// Records and emission
// ---------------------------------------------------------------------------

/// One bounded structured diagnostic record: a stable event code plus the
/// already-sanitized `key='value'` field line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticRecord {
    event: &'static str,
    line: String,
}

impl DiagnosticRecord {
    /// Returns the stable event code.
    #[must_use]
    pub const fn event(&self) -> &'static str {
        self.event
    }

    /// Returns the full bounded record line.
    #[must_use]
    pub fn line(&self) -> &str {
        &self.line
    }

    /// Returns true when the record line contains the substring.
    #[must_use]
    pub fn contains(&self, needle: &str) -> bool {
        self.line.contains(needle)
    }
}

/// Emits one bounded record to the `tracing` sink and the active
/// thread-local capture, then returns it for assertion.
fn emit_line(event: &'static str, fields: &str) -> DiagnosticRecord {
    let line = format!("event='{event}' {fields}");
    push_capture(&line);
    tracing::info!(target: "eliotd::diagnostics", event = %event, record = %line);
    DiagnosticRecord { event, line }
}

/// Sink failure from [`emit_to_writer`]: the allowed minimal fallback
/// without recursive logging, panic, or fabricated success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkError {
    /// The fallback writer rejected the record; carries the bounded detail.
    WriteFailed(String),
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WriteFailed(detail) => {
                write!(formatter, "diagnostic sink write failed: {detail}")
            }
        }
    }
}

impl std::error::Error for SinkError {}

/// Writes one record to an explicit fallback writer (never stdout, never a
/// protocol frame).
///
/// # Errors
///
/// Returns [`SinkError::WriteFailed`] when the writer rejects the record.
pub fn emit_to_writer(
    writer: &mut dyn std::io::Write,
    record: &DiagnosticRecord,
) -> Result<(), SinkError> {
    writer
        .write_all(record.line.as_bytes())
        .map_err(|error| SinkError::WriteFailed(sanitize_detail(&error.to_string())))?;
    writer
        .write_all(b"\n")
        .map_err(|error| SinkError::WriteFailed(sanitize_detail(&error.to_string())))?;
    Ok(())
}

/// Emits the binary startup record. Called once from binary startup after
/// [`init_daemon_diagnostics`].
pub fn emit_startup() -> DiagnosticRecord {
    emit_line(
        "eliotd.startup",
        &format!("service='{SERVICE_NAME}' protocol='{PROTOCOL_VERSION}' sink='stderr'"),
    )
}

/// Emits the Kernel handshake observation (transport connect/session
/// validation). This is not semantic readiness.
pub fn emit_kernel_handshake(connection_id: &str, validated: bool) -> DiagnosticRecord {
    let connection = sanitize_identity(connection_id);
    let state = if validated { "validated" } else { "connected" };
    emit_line(
        "eliotd.kernel_handshake",
        &format!("connection='{connection}' state='{state}'"),
    )
}

/// Emits the daemon readiness observation (Governor recovery + attach gates
/// passed, or the exact degraded/not-ready state). This is not the Kernel
/// handshake.
pub fn emit_daemon_readiness(ready: bool, degraded: bool) -> DiagnosticRecord {
    let state = if ready && !degraded {
        "ready"
    } else if degraded {
        "degraded"
    } else {
        "not_ready"
    };
    emit_line(
        "eliotd.daemon_readiness",
        &format!("service='{SERVICE_NAME}' state='{state}'"),
    )
}

/// Request receipt: exact available request/operation identity, never
/// payload content. The constructor takes no payload parameter by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestReceipt {
    request_id: String,
    operation_id: String,
}

impl RequestReceipt {
    /// Builds the receipt identity from already-validated ids.
    #[must_use]
    pub fn of(request_id: &str, operation_id: &str) -> Self {
        Self {
            request_id: sanitize_identity(request_id),
            operation_id: sanitize_identity(operation_id),
        }
    }

    /// Emits the receipt record.
    pub fn emit(&self) -> DiagnosticRecord {
        emit_line(
            "eliotd.request_receipt",
            &format!(
                "request='{}' operation='{}'",
                self.request_id, self.operation_id
            ),
        )
    }
}

/// Resolved `WorkScope`, task and State-Fence identities, preserved exactly
/// as their owner supplied them (or [`UNAVAILABLE`] when absent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeIdentities {
    scope_id: String,
    task_id: String,
    fence: String,
}

impl ScopeIdentities {
    /// Builds the identity triple from already-validated owner values.
    #[must_use]
    pub fn of(scope_id: &str, task_id: &str, fence: &str) -> Self {
        Self {
            scope_id: sanitize_identity(scope_id),
            task_id: sanitize_identity(task_id),
            fence: sanitize_identity(fence),
        }
    }

    /// Emits the resolution record.
    pub fn emit(&self) -> DiagnosticRecord {
        emit_line(
            "eliotd.scope_resolved",
            &format!(
                "scope='{}' task='{}' fence='{}'",
                self.scope_id, self.task_id, self.fence
            ),
        )
    }
}

/// The eight daemon admission states. Candidate, admitted, rejected, staged,
/// committed, unknown, reconciled and finished stay distinct; diagnostics
/// never coerce one into another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDisposition {
    /// Observed but not yet decided.
    Candidate,
    /// Semantically admitted by the owner.
    Admitted,
    /// Rejected with a typed reason and owner.
    Rejected,
    /// Kernel reservation staged for the exact frozen definition.
    Staged,
    /// Admission committed by the owner receipt.
    Committed,
    /// Unresolved; original identity retained, no resend triggered.
    Unknown,
    /// Reconciled from Kernel retention after a lost acknowledgement.
    Reconciled,
    /// Finished only when the authoritative Finish result supports it.
    Finished,
}

impl AdmissionDisposition {
    /// Returns the stable disposition code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Admitted => "admitted",
            Self::Rejected => "rejected",
            Self::Staged => "staged",
            Self::Committed => "committed",
            Self::Unknown => "unknown",
            Self::Reconciled => "reconciled",
            Self::Finished => "finished",
        }
    }

    /// Returns every disposition in declaration order.
    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::Candidate,
            Self::Admitted,
            Self::Rejected,
            Self::Staged,
            Self::Committed,
            Self::Unknown,
            Self::Reconciled,
            Self::Finished,
        ]
    }
}

/// Projects one typed activation-resolution disposition to the daemon
/// admission vocabulary without coercion: selection stays candidate,
/// transient `NotReady` and internal failure stay unknown, stale fence is
/// the only rejection here, and nothing maps to finished.
#[must_use]
pub const fn disposition_of_resolution(
    disposition: &AgentActivationResolutionDisposition,
) -> AdmissionDisposition {
    match disposition {
        AgentActivationResolutionDisposition::Resolved { .. } => AdmissionDisposition::Admitted,
        AgentActivationResolutionDisposition::TaskSelectionRequired { .. }
        | AgentActivationResolutionDisposition::ScopeSelectionRequired { .. }
        | AgentActivationResolutionDisposition::ScopeAmbiguous { .. } => {
            AdmissionDisposition::Candidate
        }
        AgentActivationResolutionDisposition::NotReady { .. }
        | AgentActivationResolutionDisposition::FailedInternal { .. } => {
            AdmissionDisposition::Unknown
        }
        AgentActivationResolutionDisposition::StaleFence { .. } => AdmissionDisposition::Rejected,
    }
}

/// Projects one staged Kernel reservation to its admission disposition.
#[must_use]
pub fn disposition_of_reservation(_reservation: &Reservation) -> AdmissionDisposition {
    AdmissionDisposition::Staged
}

/// Projects one committed fabric admission receipt to its disposition.
#[must_use]
pub fn disposition_of_admission(_admission: &FabricAdmission) -> AdmissionDisposition {
    AdmissionDisposition::Committed
}

/// Semantic admission record: actual admitted/rejected disposition plus the
/// deterministic admission digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRecord {
    disposition: AdmissionDisposition,
    digest: String,
    request_id: String,
}

impl AdmissionRecord {
    /// Builds an admission record over the sanitized request identity.
    #[must_use]
    pub fn of(disposition: AdmissionDisposition, request_id: &str, digest: &str) -> Self {
        Self {
            disposition,
            digest: sanitize_identity(digest),
            request_id: sanitize_identity(request_id),
        }
    }

    /// Emits the admission record.
    pub fn emit(&self) -> DiagnosticRecord {
        emit_line(
            "eliotd.admission_decided",
            &format!(
                "disposition='{}' digest='{}' request='{}'",
                self.disposition.as_str(),
                self.digest,
                self.request_id
            ),
        )
    }
}

/// `PreparedTransition` handoff versus committed transition. A prepared
/// handoff is not a committed transition; the two use distinct events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffKind {
    /// Identity-bound prepared handoff validated before transport.
    Prepared,
    /// Committed transition backed by the validated owner receipt.
    Committed,
}

impl HandoffKind {
    /// Returns the stable event code; the two kinds never share one.
    #[must_use]
    pub const fn event(self) -> &'static str {
        match self {
            Self::Prepared => "eliotd.transition_handoff",
            Self::Committed => "eliotd.transition_committed",
        }
    }
}

/// Emits the handoff/commitment record over validated identities.
pub fn emit_handoff(kind: HandoffKind, operation_id: &str, digest: &str) -> DiagnosticRecord {
    let operation = sanitize_identity(operation_id);
    let digest = sanitize_identity(digest);
    emit_line(
        kind.event(),
        &format!("operation='{operation}' digest='{digest}'"),
    )
}

/// Typed candidate-rejection reason. Stale fence stays separate from generic
/// failure; refusal stays separate from failed execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// Presented fence is stale or mismatched.
    StaleFence,
    /// Presented epoch is stale or mismatched.
    StaleEpoch,
    /// Reservation is stale, unknown, or already consumed.
    StaleReservation,
    /// Admission is stale, cancelled, or superseded.
    StaleAdmission,
    /// Governor denied admission.
    AdmissionDenied,
    /// Admission arrived incomplete and cannot run.
    AdmissionIncomplete,
    /// Governor narrowed the proposal.
    Narrowed,
    /// Admission needs a revised owner proposal.
    NeedsProposal,
    /// No eligible route; typed outcome, never a local fallback.
    NoRoute,
    /// Local wiring contract violation.
    Contract,
    /// Receipt does not bind the exact definition digest and reservation.
    ReceiptBinding,
    /// A second launch was attempted for an already-registered operation.
    DuplicateLaunch,
    /// Observation quarantined through supervision; publishes nothing.
    Quarantined,
    /// Admission was cancelled or superseded before activation.
    Cancelled,
    /// Coordinator unavailable for this operation.
    CoordinatorUnavailable,
    /// Dispatch egress unavailable or lost without retention.
    DispatchUnavailable,
    /// Unknown child outcome; cannot satisfy Finish.
    UnknownChild,
    /// Refused without failed execution.
    Refused,
    /// Generic failure with no narrower typed reason.
    GenericFailure,
}

impl RejectionReason {
    /// Returns the stable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleFence => "stale-fence",
            Self::StaleEpoch => "stale-epoch",
            Self::StaleReservation => "stale-reservation",
            Self::StaleAdmission => "stale-admission",
            Self::AdmissionDenied => "admission-denied",
            Self::AdmissionIncomplete => "admission-incomplete",
            Self::Narrowed => "narrowed",
            Self::NeedsProposal => "needs-proposal",
            Self::NoRoute => "no-route",
            Self::Contract => "contract",
            Self::ReceiptBinding => "receipt-binding",
            Self::DuplicateLaunch => "duplicate-launch",
            Self::Quarantined => "quarantined",
            Self::Cancelled => "cancelled",
            Self::CoordinatorUnavailable => "coordinator-unavailable",
            Self::DispatchUnavailable => "dispatch-unavailable",
            Self::UnknownChild => "unknown-child",
            Self::Refused => "refused",
            Self::GenericFailure => "generic-failure",
        }
    }

    /// Returns true only for the stale-fence reason.
    #[must_use]
    pub const fn is_stale_fence(self) -> bool {
        matches!(self, Self::StaleFence)
    }
}

/// Exact owning component of a rejection or error record. The owner is the
/// boundary that already observed the evidence, never a guess from status
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwningComponent {
    /// Governor semantic admission owner.
    Governor,
    /// Kernel transport/fence/reservation owner.
    Kernel,
    /// Daemon config boundary.
    DaemonConfig,
    /// Daemon runtime loop.
    DaemonRuntime,
    /// Activation projection boundary.
    ActivationProjection,
    /// Transition transport adapter.
    TransitionPort,
    /// Recovery transport adapter.
    RecoveryPort,
    /// Durable agent-fabric wiring.
    AgentFabric,
    /// Coordinator owner behind the fabric.
    Coordinator,
    /// Dispatch egress seam.
    DispatchEgress,
    /// Model registry seam.
    ModelRegistry,
    /// Admission authority seam.
    AdmissionAuthority,
}

impl OwningComponent {
    /// Returns the stable owner code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Governor => "governor",
            Self::Kernel => "kernel",
            Self::DaemonConfig => "daemon-config",
            Self::DaemonRuntime => "daemon-runtime",
            Self::ActivationProjection => "activation-projection",
            Self::TransitionPort => "transition-port",
            Self::RecoveryPort => "recovery-port",
            Self::AgentFabric => "agent-fabric",
            Self::Coordinator => "coordinator",
            Self::DispatchEgress => "dispatch-egress",
            Self::ModelRegistry => "model-registry",
            Self::AdmissionAuthority => "admission-authority",
        }
    }
}

/// Maps one fabric owner error to its typed rejection reason plus exact
/// owning component. The match is exhaustive over [`FabricError`]; no
/// variant falls through to a guessed owner.
#[must_use]
pub fn fabric_rejection_of(error: &FabricError) -> (RejectionReason, OwningComponent) {
    match error {
        FabricError::NotReady(_)
        | FabricError::Contract(_)
        | FabricError::DefinitionConflict(_)
        | FabricError::IdentityConflict(_)
        | FabricError::ReceiptBinding(_)
        | FabricError::DuplicateLaunch(_)
        | FabricError::AlreadyInitialized(_)
        | FabricError::AckNotResult(_)
        | FabricError::ResultNotFinish(_)
        | FabricError::NotActivated(_)
        | FabricError::Quarantined(_) => {
            let reason = match error {
                FabricError::ReceiptBinding(_) => RejectionReason::ReceiptBinding,
                FabricError::DuplicateLaunch(_) => RejectionReason::DuplicateLaunch,
                FabricError::Quarantined(_) => RejectionReason::Quarantined,
                _ => RejectionReason::Contract,
            };
            (reason, OwningComponent::AgentFabric)
        }
        FabricError::Coordinator(_) | FabricError::CoordinatorUnavailable(_) => (
            RejectionReason::CoordinatorUnavailable,
            OwningComponent::Coordinator,
        ),
        FabricError::AdmissionDenied(_) => {
            (RejectionReason::AdmissionDenied, OwningComponent::Governor)
        }
        FabricError::AdmissionIncomplete(_) => (
            RejectionReason::AdmissionIncomplete,
            OwningComponent::Governor,
        ),
        FabricError::Narrowed(_) => (RejectionReason::Narrowed, OwningComponent::Governor),
        FabricError::NeedsTask(_)
        | FabricError::NeedsScope(_)
        | FabricError::NeedsSource(_)
        | FabricError::NeedsCapability(_)
        | FabricError::NeedsSupervision(_) => {
            (RejectionReason::NeedsProposal, OwningComponent::Governor)
        }
        FabricError::StaleFence(_) => (RejectionReason::StaleFence, OwningComponent::Kernel),
        FabricError::StaleEpoch(_) => (RejectionReason::StaleEpoch, OwningComponent::Kernel),
        FabricError::StaleReservation(_) => {
            (RejectionReason::StaleReservation, OwningComponent::Kernel)
        }
        FabricError::StaleAdmission(_) => {
            (RejectionReason::StaleAdmission, OwningComponent::Kernel)
        }
        FabricError::Cancelled(_)
        | FabricError::Superseded(_)
        | FabricError::CancellationRequested(_)
        | FabricError::TerminalCancellation(_) => {
            (RejectionReason::Cancelled, OwningComponent::Kernel)
        }
        FabricError::NoRoute(_) => (RejectionReason::NoRoute, OwningComponent::ModelRegistry),
        FabricError::DispatchUnavailable(_) | FabricError::DispatchLost(_) => (
            RejectionReason::DispatchUnavailable,
            OwningComponent::DispatchEgress,
        ),
        FabricError::UnknownChild(_) => {
            (RejectionReason::UnknownChild, OwningComponent::AgentFabric)
        }
    }
}

/// Maps one daemon error to its reporting owner. Lifecycle/config/transport
/// boundaries report themselves; only the Governor composition owner maps
/// to [`OwningComponent::Governor`]. The error text is never parsed for
/// ownership.
#[must_use]
pub fn daemon_error_owner(error: &DaemonError) -> OwningComponent {
    match error {
        DaemonError::Composition(_) => OwningComponent::Governor,
        DaemonError::Kernel(_) => OwningComponent::Kernel,
        DaemonError::LaunchConfig(_) | DaemonError::Protected(_) => OwningComponent::DaemonConfig,
        DaemonError::Lifecycle(_) => OwningComponent::DaemonRuntime,
    }
}

/// Candidate-rejection record: typed reason plus exact owning component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectionRecord {
    reason: RejectionReason,
    owner: OwningComponent,
    detail: String,
}

impl RejectionRecord {
    /// Builds the rejection record; detail is bounded and redacted.
    #[must_use]
    pub fn of(reason: RejectionReason, owner: OwningComponent, detail: &str) -> Self {
        Self {
            reason,
            owner,
            detail: sanitize_detail(detail),
        }
    }

    /// Builds the rejection record directly from a fabric owner error.
    #[must_use]
    pub fn of_fabric_error(error: &FabricError) -> Self {
        let (reason, owner) = fabric_rejection_of(error);
        Self::of(reason, owner, &error.to_string())
    }

    /// Emits the rejection record.
    pub fn emit(&self) -> DiagnosticRecord {
        emit_line(
            "eliotd.candidate_rejected",
            &format!(
                "reason='{}' owner='{}' detail='{}'",
                self.reason.as_str(),
                self.owner.as_str(),
                self.detail
            ),
        )
    }
}

/// Cache rebuild states stay distinct from each other and from cache
/// health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebuildState {
    /// Rebuild requested by the owner.
    Requested,
    /// Rebuild in progress under the owner.
    InProgress,
    /// Rebuild completed with owner evidence.
    Completed,
}

impl RebuildState {
    /// Returns the stable rebuild code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "rebuild-requested",
            Self::InProgress => "rebuild-in-progress",
            Self::Completed => "rebuild-completed",
        }
    }
}

/// Cache health states stay distinct from rebuild states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheState {
    /// Cache healthy per owner evidence.
    Healthy,
    /// Cache degraded per owner evidence.
    Degraded,
}

impl CacheState {
    /// Returns the stable cache code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "cache-healthy",
            Self::Degraded => "cache-degraded",
        }
    }
}

/// Emits the rebuild-state record over the owner digest identity.
pub fn emit_rebuild(state: RebuildState, digest: &str) -> DiagnosticRecord {
    let digest = sanitize_identity(digest);
    emit_line(
        "eliotd.cache_rebuild",
        &format!("state='{}' digest='{digest}'", state.as_str()),
    )
}

/// Emits the cache-health record over the owner digest identity.
pub fn emit_cache_health(state: CacheState, digest: &str) -> DiagnosticRecord {
    let digest = sanitize_identity(digest);
    emit_line(
        "eliotd.cache_health",
        &format!("state='{}' digest='{digest}'", state.as_str()),
    )
}

/// Strict-Finish evaluation is visible without becoming a finish claim.
/// Completion is the identity passthrough of the authoritative Finish
/// result: diagnostics never invent it.
#[must_use]
pub const fn strict_finish_completed(authoritative_finish_supported: bool) -> bool {
    authoritative_finish_supported
}

/// Emits the strict-Finish evaluation record. `completed` must be the
/// authoritative result passthrough ([`strict_finish_completed`]), never a
/// locally synthesized success.
pub fn emit_finish_evaluation(attempt_id: &str, completed: bool) -> DiagnosticRecord {
    let attempt = sanitize_identity(attempt_id);
    let completed_text = if completed { "true" } else { "false" };
    emit_line(
        "eliotd.finish_evaluated",
        &format!("attempt='{attempt}' completed='{completed_text}'"),
    )
}

/// Emits the strict-Finish refusal record: refusal without fabricated
/// completion.
pub fn emit_finish_refusal(
    attempt_id: &str,
    reason: RejectionReason,
    owner: OwningComponent,
) -> DiagnosticRecord {
    let attempt = sanitize_identity(attempt_id);
    emit_line(
        "eliotd.finish_refused",
        &format!(
            "attempt='{attempt}' completed='false' reason='{}' owner='{}'",
            reason.as_str(),
            owner.as_str()
        ),
    )
}

/// Drain disposition for an in-flight activation when shutdown arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// No activation was in flight; plain shutdown.
    Idle,
    /// In-flight activation drained with unknown retention; original
    /// identity preserved verbatim.
    ActivationUnknown,
}

impl DrainOutcome {
    /// Returns the stable drain code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "drain-idle",
            Self::ActivationUnknown => "drain-activation-unknown",
        }
    }
}

/// Emits the drain record.
pub fn emit_drain(outcome: DrainOutcome, ticket_id: &str, result_sha256: &str) -> DiagnosticRecord {
    let ticket = sanitize_identity(ticket_id);
    let result = sanitize_identity(result_sha256);
    emit_line(
        "eliotd.drain",
        &format!(
            "disposition='{}' ticket='{ticket}' result='{result}'",
            outcome.as_str()
        ),
    )
}

/// Shutdown disposition of the daemon composition owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// Clean shutdown; composition stopped.
    Clean,
    /// Shutdown with an unknown activation retained verbatim.
    WithActivationUnknown,
    /// Shutdown path itself failed closed.
    WithError,
}

impl ShutdownOutcome {
    /// Returns the stable shutdown code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "shutdown-clean",
            Self::WithActivationUnknown => "shutdown-activation-unknown",
            Self::WithError => "shutdown-error",
        }
    }
}

/// Emits the shutdown record.
pub fn emit_shutdown(outcome: ShutdownOutcome, detail: &str) -> DiagnosticRecord {
    let detail = sanitize_detail(detail);
    emit_line(
        "eliotd.shutdown",
        &format!("disposition='{}' detail='{detail}'", outcome.as_str()),
    )
}

/// A candidate or worker acknowledgement is never completed work. The
/// outcome is carried for correlation only; the return is always false.
#[must_use]
pub fn ack_is_completed(_outcome: &AgentActivationResultAckOutcome) -> bool {
    false
}

/// Emits the worker-acknowledgement record with `completed='false'`.
pub fn emit_worker_ack(attempt_id: &str, worker_id: &str) -> DiagnosticRecord {
    let attempt = sanitize_identity(attempt_id);
    let worker = sanitize_identity(worker_id);
    emit_line(
        "eliotd.worker_ack",
        &format!("attempt='{attempt}' worker='{worker}' completed='false'"),
    )
}

/// Process exit is never completed work.
#[must_use]
pub const fn process_exit_is_completed() -> bool {
    false
}

/// Emits the process-exit record with `completed='false'`.
pub fn emit_process_exit(process_id: &str, exit_code: i32) -> DiagnosticRecord {
    let process = sanitize_identity(process_id);
    emit_line(
        "eliotd.process_exited",
        &format!("process='{process}' exit='{exit_code}' completed='false'"),
    )
}

/// A successful response write is never completed work.
#[must_use]
pub const fn response_write_is_completed() -> bool {
    false
}

/// Emits the response-write record with `completed='false'`.
pub fn emit_response_write(operation_id: &str) -> DiagnosticRecord {
    let operation = sanitize_identity(operation_id);
    emit_line(
        "eliotd.response_written",
        &format!("operation='{operation}' completed='false'"),
    )
}

/// Owning error record: one record per inventoried failed daemon operation
/// at its owning boundary. Fields and records are bounded; repeated
/// failures are capped by [`RepeatedFailureGuard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorRecord {
    owner: OwningComponent,
    code: String,
    detail: String,
}

impl ErrorRecord {
    /// Builds the error record; code and detail are bounded and redacted.
    #[must_use]
    pub fn of(owner: OwningComponent, code: &str, detail: &str) -> Self {
        Self {
            owner,
            code: sanitize_identity(code),
            detail: sanitize_detail(detail),
        }
    }

    /// Builds the error record from a daemon error at its reporting owner.
    #[must_use]
    pub fn of_daemon_error(error: &DaemonError) -> Self {
        let owner = daemon_error_owner(error);
        let (code, detail) = match error {
            DaemonError::Composition(_) => ("composition", error.to_string()),
            DaemonError::Kernel(_) => ("kernel-transport", error.to_string()),
            DaemonError::LaunchConfig(_) => ("launch-config", error.to_string()),
            DaemonError::Protected(_) => ("protected-path", error.to_string()),
            DaemonError::Lifecycle(_) => ("lifecycle", error.to_string()),
        };
        Self::of(owner, code, &detail)
    }

    /// Builds the error record from a fabric owner error.
    #[must_use]
    pub fn of_fabric_error(error: &FabricError) -> Self {
        let (_, owner) = fabric_rejection_of(error);
        Self::of(owner, "fabric", &error.to_string())
    }

    /// Emits the error record.
    pub fn emit(&self) -> DiagnosticRecord {
        emit_line(
            "eliotd.operation_error",
            &format!(
                "owner='{}' code='{}' detail='{}'",
                self.owner.as_str(),
                self.code,
                self.detail
            ),
        )
    }
}

/// Caps repeated-failure output: the first [`MAX_REPEATED_FAILURE_LINES`]
/// failures emit, the rest only increment the suppressed count. No
/// unbounded buffer, no critical-path lock, no extra owner calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeatedFailureGuard {
    emitted: u64,
    suppressed: u64,
}

impl RepeatedFailureGuard {
    /// Creates an unused guard.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            emitted: 0,
            suppressed: 0,
        }
    }

    /// Returns true while the failure line may still be emitted.
    pub fn should_emit(&mut self) -> bool {
        if self.emitted < MAX_REPEATED_FAILURE_LINES {
            self.emitted = self.emitted.saturating_add(1);
            true
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            false
        }
    }

    /// Returns the emitted line count.
    #[must_use]
    pub const fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Returns the suppressed line count.
    #[must_use]
    pub const fn suppressed(&self) -> u64 {
        self.suppressed
    }
}

impl Default for RepeatedFailureGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Kernel disconnect observation: the exact unavailable/unknown state under
/// the original connection identity. Pure value: emitting or recording it
/// performs no IO and never triggers a resend, reconciliation, or new
/// semantic decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelDisconnect {
    connection_id: String,
}

impl KernelDisconnect {
    /// Builds the disconnect observation from the validated connection id.
    #[must_use]
    pub fn of(connection_id: &str) -> Self {
        Self {
            connection_id: sanitize_identity(connection_id),
        }
    }

    /// Emits the disconnect record with `state='unknown'`.
    pub fn emit(&self) -> DiagnosticRecord {
        emit_line(
            "eliotd.kernel_disconnect",
            &format!(
                "connection='{}' state='{STATE_UNKNOWN}'",
                self.connection_id
            ),
        )
    }
}

/// Emits the Kernel activation-result acknowledgement record.
///
/// The acknowledgement outcome (`accepted`, `exact-replay`, `reconciled`,
/// `unknown`) is correlation only: an acknowledgement is never completed
/// work, so the record carries no completion claim. `Unknown` preserves the
/// original ticket/result identity verbatim for the shutdown drain.
pub fn emit_activation_ack(
    ticket_id: &str,
    result_sha256: &str,
    outcome: &AgentActivationResultAckOutcome,
) -> DiagnosticRecord {
    let ticket = sanitize_identity(ticket_id);
    let result = sanitize_identity(result_sha256);
    let outcome_text = match outcome {
        AgentActivationResultAckOutcome::Accepted => "accepted",
        AgentActivationResultAckOutcome::ExactReplay => "exact-replay",
        AgentActivationResultAckOutcome::Reconciled => "reconciled",
        AgentActivationResultAckOutcome::Unknown => STATE_UNKNOWN,
    };
    emit_line(
        "eliotd.activation_ack",
        &format!("ticket='{ticket}' result='{result}' outcome='{outcome_text}'"),
    )
}

/// Emits the #872 agent-fabric attach record over the admitted descriptor
/// identities (service, generation, epoch).
pub fn emit_fabric_attached(
    service: &str,
    generation: u64,
    authority_epoch: u64,
) -> DiagnosticRecord {
    let service = sanitize_identity(service);
    emit_line(
        "eliotd.fabric_attached",
        &format!("service='{service}' generation='{generation}' epoch='{authority_epoch}'"),
    )
}
