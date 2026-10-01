//! Watchdog challenge/recovery audit records (issue #1757 W1; I8.3, I13.11).
//!
//! Every challenge, timeout, denial, budget decision, SCM request, and
//! readback is correlated by operation, policy, and target identity
//! (operation id, policy digest, target service/generation, owner digest).
//! Spool persistence and Event Log delivery are independent facts: this cell
//! hands records to the bounded async writer through a finite non-blocking
//! handoff and never replays an SCM effect to retry its log. Delivery failure
//! and pending state are recorded, never silent, and never promoted into a
//! duplicate restart.
//!
//! The installed Event Log source/event contract is extended only through its
//! owner: the Watchdog requests the `EliotWatchdog` source with events
//! 300–311 below, coordinated with #984/#889. This cell performs no Event Log
//! FFI, never uses the `EliotHost` source, and never passes an arbitrary
//! source name. The single insertion string rendered here is already redacted
//! and bounded; bounding limits size, not sensitivity.
//!
//! Redaction: only digests and coordination identities enter a record.
//! Credentials, nonces, raw paths, and user data are refused at construction,
//! never truncated into acceptability.

use thiserror::Error;

/// Bound for one audit detail string, in characters.
pub const WATCHDOG_AUDIT_DETAIL_MAX_CHARS: usize = 1024;

/// Capacity of the finite async handoff to the bounded audit writer.
pub const WATCHDOG_AUDIT_HANDOFF_CAPACITY: usize = 64;

/// Requested installed Event Log source for Watchdog challenge/recovery
/// records. Effective only through the #984/#889 owner that installs sources;
/// this cell never reports through `EliotHost`.
pub const WATCHDOG_EVENT_LOG_SOURCE: &str = "EliotWatchdog";

/// Admitted Watchdog challenge/recovery audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeAuditEvent {
    /// A challenge was issued with its installation/policy binding.
    Issued,
    /// The control owner answered the exact challenge within its bound.
    Answered,
    /// A competently attempted challenge timed out: ALIVE_UNRESPONSIVE.
    TimedOut,
    /// The challenger could not authenticate to the owner path.
    Unauthenticated,
    /// The connection was denied before any owner answer.
    ConnectionDenied,
    /// The live target changed across the observation interval.
    TargetChanged,
    /// Sensor coverage was inadequate for a competent attempt.
    InadequateCoverage,
    /// One fenced recovery attempt was admitted under the installed budget.
    BudgetAdmitted,
    /// The installed budget is exhausted or missing: zero SCM effects.
    BudgetExhausted,
    /// One fenced SCM effect was requested through the Host-state lane.
    ScmRequested,
    /// The SCM readback for a requested effect was observed.
    ScmReadback,
    /// Audit delivery is still pending behind the bounded writer.
    DeliveryPending,
    /// Audit delivery failed and is recorded without an SCM replay.
    DeliveryFailed,
}

impl ChallengeAuditEvent {
    /// Stable diagnostic name. Every variant maps to a distinct string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Answered => "answered",
            Self::TimedOut => "timed_out",
            Self::Unauthenticated => "unauthenticated",
            Self::ConnectionDenied => "connection_denied",
            Self::TargetChanged => "target_changed",
            Self::InadequateCoverage => "inadequate_coverage",
            Self::BudgetAdmitted => "budget_admitted",
            Self::BudgetExhausted => "budget_exhausted",
            Self::ScmRequested => "scm_requested",
            Self::ScmReadback => "scm_readback",
            Self::DeliveryPending => "delivery_pending",
            Self::DeliveryFailed => "delivery_failed",
        }
    }

    /// Requested installed Event Log identifier for this event (300–312).
    /// Admitted only through the #984/#889 source owner, never direct FFI.
    #[must_use]
    pub const fn event_id(self) -> u32 {
        match self {
            Self::Issued => 300,
            Self::Answered => 301,
            Self::TimedOut => 302,
            Self::Unauthenticated => 303,
            Self::ConnectionDenied => 304,
            Self::TargetChanged => 305,
            Self::InadequateCoverage => 306,
            Self::BudgetAdmitted => 307,
            Self::BudgetExhausted => 308,
            Self::ScmRequested => 309,
            Self::ScmReadback => 310,
            Self::DeliveryPending => 311,
            Self::DeliveryFailed => 312,
        }
    }
}

/// Typed audit-record failure. Identity names and stable reason codes only.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ChallengeAuditError {
    #[error("watchdog audit identity is blank: {0}")]
    BlankIdentity(&'static str),
    #[error("watchdog audit detail carries protected material: {0}")]
    ForbiddenDetail(&'static str),
    #[error("watchdog audit handoff receiver is closed")]
    ChannelClosed,
}

/// One correlated Watchdog challenge/recovery audit record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeAuditRecord {
    pub operation_id: String,
    pub policy_digest: String,
    pub target_service: String,
    pub target_generation: String,
    pub owner_digest: String,
    pub event: ChallengeAuditEvent,
    pub observed_at_ms: u64,
    pub detail: String,
}

/// Substrings that never enter an audit detail, matched case-insensitively.
/// Bounding limits size, not sensitivity: protected material is refused, not
/// truncated into acceptability.
const FORBIDDEN_DETAIL_MARKERS: &[&str] = &[
    "password", "secret", "token", "credential", "private_key", "nonce", r"\\", "c:\\", "c:/",
];

fn redacted_detail(value: &str) -> Result<String, ChallengeAuditError> {
    if value.chars().any(char::is_control) {
        return Err(ChallengeAuditError::ForbiddenDetail("control characters"));
    }
    let lowered = value.to_lowercase();
    for marker in FORBIDDEN_DETAIL_MARKERS {
        if lowered.contains(marker) {
            return Err(ChallengeAuditError::ForbiddenDetail("protected material"));
        }
    }
    if value.chars().count() > WATCHDOG_AUDIT_DETAIL_MAX_CHARS {
        Ok(value.chars().take(WATCHDOG_AUDIT_DETAIL_MAX_CHARS).collect())
    } else {
        Ok(value.to_owned())
    }
}

fn audit_identity(value: &str, field: &'static str) -> Result<String, ChallengeAuditError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ChallengeAuditError::BlankIdentity(field));
    }
    Ok(value.to_owned())
}

impl ChallengeAuditRecord {
    /// Builds one correlated audit record.
    ///
    /// # Errors
    ///
    /// Returns [`ChallengeAuditError`] for a blank correlation identity or
    /// for detail carrying protected material.
    pub fn new(
        operation_id: &str,
        policy_digest: &str,
        target_service: &str,
        target_generation: &str,
        owner_digest: &str,
        event: ChallengeAuditEvent,
        observed_at_ms: u64,
        detail: &str,
    ) -> Result<Self, ChallengeAuditError> {
        Ok(Self {
            operation_id: audit_identity(operation_id, "operation")?,
            policy_digest: audit_identity(policy_digest, "policy")?,
            target_service: audit_identity(target_service, "target service")?,
            target_generation: audit_identity(target_generation, "target generation")?,
            owner_digest: audit_identity(owner_digest, "owner")?,
            event,
            observed_at_ms,
            detail: redacted_detail(detail)?,
        })
    }

    /// Renders the already-redacted single insertion string for the installed
    /// Event Log source. Coordination identities and the stable event name
    /// only; at most [`WATCHDOG_AUDIT_DETAIL_MAX_CHARS`] characters.
    #[must_use]
    pub fn event_log_insertion(&self) -> String {
        let rendered = format!(
            "{} op={} policy={} target={} generation={} owner={} detail={}",
            self.event.as_str(),
            self.operation_id,
            self.policy_digest,
            self.target_service,
            self.target_generation,
            self.owner_digest,
            self.detail,
        );
        if rendered.chars().count() > WATCHDOG_AUDIT_DETAIL_MAX_CHARS {
            rendered.chars().take(WATCHDOG_AUDIT_DETAIL_MAX_CHARS).collect()
        } else {
            rendered
        }
    }
}

/// Delivery disposition of one handed-off audit record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditDelivery {
    /// The bounded writer accepted the record.
    Delivered,
    /// The bounded writer is full or no sink is composed; the record waits
    /// without any SCM replay.
    Pending,
    /// The writer is gone; the loss is recorded, never retried via SCM.
    Failed,
}

/// Finite async handoff to the existing bounded audit writer.
///
/// `try_hand_off` never blocks: a full channel reports [`AuditDelivery::Pending`]
/// and a closed receiver reports [`AuditDelivery::Failed`]. Timeout of a
/// waiting future does not cancel an in-flight synchronous OS call, and an
/// SCM effect is never replayed to retry its log.
#[derive(Clone, Debug)]
pub struct BoundedAuditHandoff {
    sender: tokio::sync::mpsc::Sender<ChallengeAuditRecord>,
}

impl BoundedAuditHandoff {
    /// Opens the finite handoff with [`WATCHDOG_AUDIT_HANDOFF_CAPACITY`].
    /// The caller owns the receiver at the existing bounded writer.
    #[must_use]
    pub fn open() -> (
        Self,
        tokio::sync::mpsc::Receiver<ChallengeAuditRecord>,
    ) {
        let (sender, receiver) =
            tokio::sync::mpsc::channel(WATCHDOG_AUDIT_HANDOFF_CAPACITY);
        (Self { sender }, receiver)
    }

    /// Hands one record to the bounded writer without blocking.
    #[must_use]
    pub fn try_hand_off(&self, record: ChallengeAuditRecord) -> AuditDelivery {
        match self.sender.try_send(record) {
            Ok(()) => AuditDelivery::Delivered,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => AuditDelivery::Pending,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => AuditDelivery::Failed,
        }
    }
}

/// Records one audit-handoff disposition as diagnostics.
///
/// Observation only: identities are coordination values, never secrets, and
/// the detail is the stable disposition name. Sink drop cannot change the
/// challenge verdict, the budget decision, or any SCM effect.
pub fn observe_audit_delivery(delivery: &AuditDelivery, operation_id: &str) {
    let observation = match delivery {
        AuditDelivery::Delivered => "delivered",
        AuditDelivery::Pending => "pending",
        AuditDelivery::Failed => "failed",
    };
    tracing::debug!(
        target: crate::diagnostics::WATCHDOG_DIAGNOSTICS_TARGET,
        event = "watchdog.challenge_audit_delivery",
        observation = observation,
        operation = operation_id,
        "watchdog challenge audit handoff observed"
    );
}
