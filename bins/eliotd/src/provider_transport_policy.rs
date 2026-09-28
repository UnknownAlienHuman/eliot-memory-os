//! Privileged provider transport policy layer (issue #1834).
//!
//! Contract: `I10.11` "Provider transport hardening" in
//! `docs/architecture/I10-11-external-model-bridges.md`: every privileged
//! provider transport declares connect, TLS/header, first-byte,
//! semantic-idle, overall-job, and cleanup deadlines; retryable conditions
//! with a bounded attempt count, exponential backoff with jitter, and a
//! `Retry-After` cap; a header allowlist with explicit privacy admission;
//! bounded request/response/error/event bodies; a safe public error plus a
//! restricted raw error artifact; cancellation and terminal reconciliation;
//! an authenticated loopback/IPC default for local servers; no synchronous
//! routing-log I/O on the hot path; and no exclusive route/session/state
//! lock across a provider wait.
//!
//! This cell is stateless: it owns no mutable state, performs no I/O (so no
//! routing-log write can reach the provider hot path through it), takes no
//! locks (so no route/session/state guard is ever held across a provider
//! await by this code), and mints no authority. Every model provider adapter
//! runs under one [`TransportPolicy`]; the governed default validates on the
//! governed Dreamer invoke path before the execution port is touched.
//!
//! Numeric magnitudes are explicit assumptions: `I10.11` names the six
//! deadlines, bounded retries, and body bounds without magnitudes, so the
//! `DEFAULT_*` constants below fix one bounded governed default. Stateful
//! routing follows snapshot, release lock, external call, reacquire, then
//! revision/fence validation through [`RouteSessionSnapshot`]; TTL/affinity
//! maintenance runs as a supervised bounded job through
//! [`AffinityCleanupJob`], which exposes cancellation, health, and one
//! observable [`EvictionReceipt`] per eviction.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use eliot_contracts::StateFence;

/// Governed default connect deadline, in milliseconds.
pub const DEFAULT_CONNECT_MS: u64 = 5_000;
/// Governed default TLS/header deadline, in milliseconds.
pub const DEFAULT_TLS_HEADERS_MS: u64 = 5_000;
/// Governed default first-byte deadline, in milliseconds.
pub const DEFAULT_FIRST_BYTE_MS: u64 = 30_000;
/// Governed default semantic-idle deadline, in milliseconds.
pub const DEFAULT_SEMANTIC_IDLE_MS: u64 = 60_000;
/// Governed default overall-job deadline, in milliseconds.
pub const DEFAULT_OVERALL_JOB_MS: u64 = 300_000;
/// Governed default cleanup deadline, in milliseconds.
pub const DEFAULT_CLEANUP_MS: u64 = 10_000;
/// Governed default bounded attempt count.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;
/// Governed default backoff base, in milliseconds.
pub const DEFAULT_BASE_BACKOFF_MS: u64 = 200;
/// Governed default backoff ceiling, in milliseconds.
pub const DEFAULT_MAX_BACKOFF_MS: u64 = 5_000;
/// Governed default deterministic jitter bound, in milliseconds.
pub const DEFAULT_JITTER_BOUND_MS: u64 = 100;
/// Governed default `Retry-After` cap, in milliseconds.
pub const DEFAULT_RETRY_AFTER_CAP_MS: u64 = 30_000;
/// Governed default maximum request body, in bytes.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 1_048_576;
/// Governed default maximum response body, in bytes.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4_194_304;
/// Governed default maximum error body, in bytes.
pub const DEFAULT_MAX_ERROR_BYTES: usize = 65_536;
/// Governed default maximum event body, in bytes.
pub const DEFAULT_MAX_EVENT_BYTES: usize = 262_144;
/// Upper bound any retry policy attempt count must respect.
pub const MAX_ATTEMPTS_UPPER_BOUND: u32 = 8;
/// Maximum admission/policy identity length, in bytes.
pub const MAX_ADMISSION_ID_BYTES: usize = 1_024;
/// Maximum attempt identity length, in bytes.
pub const MAX_ATTEMPT_ID_BYTES: usize = 1_024;
/// Governed default eviction cap for one cleanup run.
pub const DEFAULT_MAX_EVICTIONS_PER_RUN: usize = 256;
/// Eviction reason recorded when a TTL has passed.
pub const EVICTION_REASON_TTL_EXPIRED: &str = "ttl-expired";

/// Closed failure vocabulary for the transport-policy layer.
///
/// Variants never echo provider prose, header values, or credential
/// material; numbers and fixed field names are the only payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportPolicyError {
    /// A named deadline is zero.
    ZeroDeadline(&'static str),
    /// A named retry bound is zero, inverted, or above the upper bound.
    InvalidRetryBounds(&'static str),
    /// A named byte limit is zero.
    ZeroByteLimit(&'static str),
    /// An outbound header is outside the allowlist.
    HeaderNotAllowlisted,
    /// No privacy admission was recorded for the outbound call.
    PrivacyNotAdmitted,
    /// A named admission identity is blank or oversized.
    InvalidAdmission(&'static str),
    /// A body exceeds its bound.
    BodyTooLarge {
        /// Bound that was enforced.
        limit: usize,
        /// Observed length.
        actual: usize,
    },
    /// A route/session snapshot no longer matches live state.
    StaleSnapshot,
    /// A local IPC policy does not require authentication.
    LocalIpcUnauthenticated,
    /// A named receipt field is blank, zero, or inconsistent.
    InvalidReceipt(&'static str),
}

impl fmt::Display for TransportPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDeadline(field) => {
                write!(f, "transport deadline `{field}` must be non-zero")
            }
            Self::InvalidRetryBounds(field) => {
                write!(f, "transport retry bound `{field}` is invalid")
            }
            Self::ZeroByteLimit(field) => {
                write!(f, "transport byte limit `{field}` must be non-zero")
            }
            Self::HeaderNotAllowlisted => {
                write!(f, "outbound header is outside the allowlist")
            }
            Self::PrivacyNotAdmitted => {
                write!(f, "outbound call has no recorded privacy admission")
            }
            Self::InvalidAdmission(field) => {
                write!(f, "privacy admission `{field}` is blank or oversized")
            }
            Self::BodyTooLarge { limit, actual } => {
                write!(f, "body of {actual} bytes exceeds the {limit}-byte bound")
            }
            Self::StaleSnapshot => {
                write!(f, "route/session snapshot does not match live state")
            }
            Self::LocalIpcUnauthenticated => {
                write!(f, "local IPC policy must require authentication")
            }
            Self::InvalidReceipt(field) => {
                write!(f, "physical attempt receipt `{field}` is invalid")
            }
        }
    }
}

impl std::error::Error for TransportPolicyError {}

/// Explicit deadline budget for one provider call.
///
/// All six `I10.11` phases are required; each is a millisecond duration. The
/// overall-job limit is enforced by the caller alongside the phase timers,
/// not derived from them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlineBudget {
    /// Connect deadline, in milliseconds.
    pub connect_ms: u64,
    /// TLS/header deadline, in milliseconds.
    pub tls_headers_ms: u64,
    /// First-byte deadline, in milliseconds.
    pub first_byte_ms: u64,
    /// Semantic-idle deadline, in milliseconds.
    pub semantic_idle_ms: u64,
    /// Overall-job deadline, in milliseconds.
    pub overall_job_ms: u64,
    /// Cleanup deadline, in milliseconds.
    pub cleanup_ms: u64,
}

impl DeadlineBudget {
    /// Returns the governed default budget.
    #[must_use]
    pub const fn governed_default() -> Self {
        Self {
            connect_ms: DEFAULT_CONNECT_MS,
            tls_headers_ms: DEFAULT_TLS_HEADERS_MS,
            first_byte_ms: DEFAULT_FIRST_BYTE_MS,
            semantic_idle_ms: DEFAULT_SEMANTIC_IDLE_MS,
            overall_job_ms: DEFAULT_OVERALL_JOB_MS,
            cleanup_ms: DEFAULT_CLEANUP_MS,
        }
    }

    /// Rejects any zero phase; every phase must be an explicit bound.
    pub fn validate(&self) -> Result<(), TransportPolicyError> {
        if self.connect_ms == 0 {
            return Err(TransportPolicyError::ZeroDeadline("connect_ms"));
        }
        if self.tls_headers_ms == 0 {
            return Err(TransportPolicyError::ZeroDeadline("tls_headers_ms"));
        }
        if self.first_byte_ms == 0 {
            return Err(TransportPolicyError::ZeroDeadline("first_byte_ms"));
        }
        if self.semantic_idle_ms == 0 {
            return Err(TransportPolicyError::ZeroDeadline("semantic_idle_ms"));
        }
        if self.overall_job_ms == 0 {
            return Err(TransportPolicyError::ZeroDeadline("overall_job_ms"));
        }
        if self.cleanup_ms == 0 {
            return Err(TransportPolicyError::ZeroDeadline("cleanup_ms"));
        }
        Ok(())
    }
}

/// Typed retryable failure: the only failures a bounded retry may follow.
///
/// Anything not representable here is terminal. Each variant carries a fixed
/// public-safe diagnostic; provider prose never enters the public message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryableFailure {
    /// The connect deadline fired.
    ConnectTimeout,
    /// The TLS/header deadline fired.
    TlsHeadersTimeout,
    /// The first-byte deadline fired.
    FirstByteTimeout,
    /// The semantic-idle deadline fired.
    SemanticIdleTimeout,
    /// The provider reported a retryable status.
    RetryableStatus,
    /// The provider asked for a delayed retry.
    RetryAfter,
}

impl RetryableFailure {
    /// Returns the fixed public-safe diagnostic for this failure.
    #[must_use]
    pub const fn safe_diagnostic(self) -> &'static str {
        match self {
            Self::ConnectTimeout => "provider connect deadline exceeded",
            Self::TlsHeadersTimeout => "provider TLS/header deadline exceeded",
            Self::FirstByteTimeout => "provider first-byte deadline exceeded",
            Self::SemanticIdleTimeout => "provider semantic-idle deadline exceeded",
            Self::RetryableStatus => "provider reported a retryable status",
            Self::RetryAfter => "provider requested a capped retry delay",
        }
    }
}

/// Bounded retry policy keyed to [`RetryableFailure`].
///
/// Backoff is exponential in the 1-based failed-attempt number, capped at
/// `max_backoff_ms`, plus bounded deterministic jitter derived from the
/// attempt number (no RNG, no clock, no I/O). A provider `Retry-After` hint
/// is capped first and then honored as a floor under the computed delay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts allowed, within `1..=MAX_ATTEMPTS_UPPER_BOUND`.
    pub max_attempts: u32,
    /// Backoff base, in milliseconds.
    pub base_backoff_ms: u64,
    /// Backoff ceiling, in milliseconds.
    pub max_backoff_ms: u64,
    /// Deterministic jitter bound, in milliseconds.
    pub jitter_bound_ms: u64,
    /// `Retry-After` cap, in milliseconds.
    pub retry_after_cap_ms: u64,
}

impl RetryPolicy {
    /// Returns the governed default retry policy.
    #[must_use]
    pub const fn governed_default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            base_backoff_ms: DEFAULT_BASE_BACKOFF_MS,
            max_backoff_ms: DEFAULT_MAX_BACKOFF_MS,
            jitter_bound_ms: DEFAULT_JITTER_BOUND_MS,
            retry_after_cap_ms: DEFAULT_RETRY_AFTER_CAP_MS,
        }
    }

    /// Rejects an unbounded or inverted policy.
    pub fn validate(&self) -> Result<(), TransportPolicyError> {
        if self.max_attempts == 0 || self.max_attempts > MAX_ATTEMPTS_UPPER_BOUND {
            return Err(TransportPolicyError::InvalidRetryBounds("max_attempts"));
        }
        if self.base_backoff_ms == 0 {
            return Err(TransportPolicyError::InvalidRetryBounds("base_backoff_ms"));
        }
        if self.max_backoff_ms < self.base_backoff_ms {
            return Err(TransportPolicyError::InvalidRetryBounds("max_backoff_ms"));
        }
        if self.jitter_bound_ms > self.max_backoff_ms {
            return Err(TransportPolicyError::InvalidRetryBounds("jitter_bound_ms"));
        }
        if self.retry_after_cap_ms == 0 {
            return Err(TransportPolicyError::InvalidRetryBounds(
                "retry_after_cap_ms",
            ));
        }
        Ok(())
    }

    /// Returns the delay before the next attempt, in milliseconds.
    ///
    /// `attempt` is the 1-based number of the attempt that just failed.
    /// Arithmetic saturates, so no input can overflow or panic.
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32, retry_after_ms: Option<u64>) -> u64 {
        let shift = attempt.saturating_sub(1);
        let exponential = self
            .base_backoff_ms
            .saturating_mul(2_u64.saturating_pow(shift));
        let capped = exponential.min(self.max_backoff_ms);
        let span = self.jitter_bound_ms.saturating_add(1);
        let jitter = u64::from(attempt).wrapping_mul(37) % span;
        let delay = capped.saturating_add(jitter).min(self.max_backoff_ms);
        retry_after_ms.map_or(delay, |hint| delay.max(self.capped_retry_after(hint)))
    }

    /// Caps one provider `Retry-After` hint at the policy cap.
    #[must_use]
    pub fn capped_retry_after(&self, retry_after_ms: u64) -> u64 {
        retry_after_ms.min(self.retry_after_cap_ms)
    }
}

/// Bounded request/response/error/event body limits, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportByteLimits {
    /// Maximum request body, in bytes.
    pub max_request_bytes: usize,
    /// Maximum response body, in bytes.
    pub max_response_bytes: usize,
    /// Maximum error body, in bytes.
    pub max_error_bytes: usize,
    /// Maximum event body, in bytes.
    pub max_event_bytes: usize,
}

impl TransportByteLimits {
    /// Returns the governed default byte limits.
    #[must_use]
    pub const fn governed_default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_error_bytes: DEFAULT_MAX_ERROR_BYTES,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
        }
    }

    /// Rejects any zero bound.
    pub fn validate(&self) -> Result<(), TransportPolicyError> {
        if self.max_request_bytes == 0 {
            return Err(TransportPolicyError::ZeroByteLimit("max_request_bytes"));
        }
        if self.max_response_bytes == 0 {
            return Err(TransportPolicyError::ZeroByteLimit("max_response_bytes"));
        }
        if self.max_error_bytes == 0 {
            return Err(TransportPolicyError::ZeroByteLimit("max_error_bytes"));
        }
        if self.max_event_bytes == 0 {
            return Err(TransportPolicyError::ZeroByteLimit("max_event_bytes"));
        }
        Ok(())
    }

    /// Rejects a request body longer than the bound.
    pub fn check_request_len(&self, len: usize) -> Result<(), TransportPolicyError> {
        if len > self.max_request_bytes {
            return Err(TransportPolicyError::BodyTooLarge {
                limit: self.max_request_bytes,
                actual: len,
            });
        }
        Ok(())
    }

    /// Rejects a response body longer than the bound.
    pub fn check_response_len(&self, len: usize) -> Result<(), TransportPolicyError> {
        if len > self.max_response_bytes {
            return Err(TransportPolicyError::BodyTooLarge {
                limit: self.max_response_bytes,
                actual: len,
            });
        }
        Ok(())
    }

    /// Rejects an error body longer than the bound.
    pub fn check_error_len(&self, len: usize) -> Result<(), TransportPolicyError> {
        if len > self.max_error_bytes {
            return Err(TransportPolicyError::BodyTooLarge {
                limit: self.max_error_bytes,
                actual: len,
            });
        }
        Ok(())
    }

    /// Rejects an event body longer than the bound.
    pub fn check_event_len(&self, len: usize) -> Result<(), TransportPolicyError> {
        if len > self.max_event_bytes {
            return Err(TransportPolicyError::BodyTooLarge {
                limit: self.max_event_bytes,
                actual: len,
            });
        }
        Ok(())
    }
}

/// Outbound header allowlist for provider calls.
///
/// Matching is case-insensitive over the trimmed header name. Header values
/// are never inspected here: credential-bearing headers stay inside the
/// owning adapter boundary and are not admitted through this path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundHeaderAllowlist;

impl OutboundHeaderAllowlist {
    /// Headers a provider call may carry.
    pub const ALLOWED: &'static [&'static str] =
        &["content-type", "accept", "user-agent", "x-request-id"];

    /// Returns true when `name` is allowlisted.
    #[must_use]
    pub fn allows(name: &str) -> bool {
        let trimmed = name.trim();
        !trimmed.is_empty()
            && Self::ALLOWED
                .iter()
                .any(|allowed| trimmed.eq_ignore_ascii_case(allowed))
    }
}

/// Recorded privacy admission gating one outbound provider call.
///
/// The admission rides from its owner; this layer only checks that it is
/// present, affirmative, and bounded. Absence fails closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivacyAdmission {
    /// True only when disclosure was explicitly admitted.
    pub admitted: bool,
    /// Owner-issued admission identity.
    pub admission_id: String,
    /// Policy revision the admission was issued under.
    pub policy_revision: String,
}

impl PrivacyAdmission {
    /// Rejects a missing, negative, blank, or oversized admission.
    pub fn validate(&self) -> Result<(), TransportPolicyError> {
        if !self.admitted {
            return Err(TransportPolicyError::PrivacyNotAdmitted);
        }
        if !is_nonblank_bounded(&self.admission_id, MAX_ADMISSION_ID_BYTES) {
            return Err(TransportPolicyError::InvalidAdmission("admission_id"));
        }
        if !is_nonblank_bounded(&self.policy_revision, MAX_ADMISSION_ID_BYTES) {
            return Err(TransportPolicyError::InvalidAdmission("policy_revision"));
        }
        Ok(())
    }
}

fn is_nonblank_bounded(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes
}

/// One transport policy every model provider adapter runs under.
///
/// Bundles the deadline budget, the bounded retry policy, and the body
/// bounds. `admit_outbound` is the single gated path: privacy admission,
/// then the header allowlist, then the request bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportPolicy {
    /// Explicit deadline budget for the call.
    pub deadlines: DeadlineBudget,
    /// Bounded retry policy for the call.
    pub retries: RetryPolicy,
    /// Body bounds for the call.
    pub byte_limits: TransportByteLimits,
}

impl TransportPolicy {
    /// Returns the governed default policy.
    #[must_use]
    pub const fn governed_default() -> Self {
        Self {
            deadlines: DeadlineBudget::governed_default(),
            retries: RetryPolicy::governed_default(),
            byte_limits: TransportByteLimits::governed_default(),
        }
    }

    /// Rejects any invalid budget, retry, or byte-limit member.
    pub fn validate(&self) -> Result<(), TransportPolicyError> {
        self.deadlines.validate()?;
        self.retries.validate()?;
        self.byte_limits.validate()?;
        Ok(())
    }

    /// Admits one outbound call under a recorded privacy admission.
    ///
    /// Order is load-bearing: the admission validates first, then every
    /// header name must be allowlisted, then the request length must fit
    /// the bound. Header values are never read, copied, or logged here.
    pub fn admit_outbound(
        &self,
        admission: &PrivacyAdmission,
        headers: &[(&str, &str)],
        request_bytes: usize,
    ) -> Result<(), TransportPolicyError> {
        admission.validate()?;
        if headers
            .iter()
            .any(|(name, _)| !OutboundHeaderAllowlist::allows(name))
        {
            return Err(TransportPolicyError::HeaderNotAllowlisted);
        }
        self.byte_limits.check_request_len(request_bytes)?;
        Ok(())
    }
}

/// Handle to a restricted raw error artifact.
///
/// Carries only a content-derived handle and the raw byte count; the raw
/// bytes themselves stay behind the restricted artifact boundary and never
/// enter the safe public message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestrictedRawErrorHandle {
    handle: String,
    raw_bytes: usize,
}

impl RestrictedRawErrorHandle {
    /// Derives the bounded handle for one raw provider error.
    #[must_use]
    pub fn for_raw(raw: &str) -> Self {
        let hash = fnv1a64(raw);
        let len = raw.len();
        Self {
            handle: format!("transport-raw-error:{hash:016x}:{len}"),
            raw_bytes: len,
        }
    }

    /// Returns the opaque restricted-artifact handle.
    #[must_use]
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// Returns the raw error length, in bytes.
    #[must_use]
    pub const fn raw_bytes(&self) -> usize {
        self.raw_bytes
    }
}

fn fnv1a64(raw: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in raw.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Splits one transport failure into its public and restricted halves.
///
/// Returns the fixed safe public message plus the restricted raw-error
/// handle. Raw provider detail never enters the public message.
#[must_use]
pub fn split_transport_error(
    failure: RetryableFailure,
    raw_detail: &str,
) -> (String, RestrictedRawErrorHandle) {
    (
        failure.safe_diagnostic().to_owned(),
        RestrictedRawErrorHandle::for_raw(raw_detail),
    )
}

/// Terminal observation available to cancellation reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedTerminal {
    /// A terminal success was observed.
    Succeeded,
    /// A terminal failure was observed.
    Failed,
    /// No terminal state was observed.
    Unobserved,
}

/// Cancellation-to-terminal reconciliation outcome.
///
/// An observed terminal always wins over a late cancellation; anything
/// unobserved reconciles to an explicit unknown-outcome disposition, never
/// to an assumed success or failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalReconciliation {
    /// Terminal success was observed.
    Succeeded,
    /// Terminal failure was observed.
    FailedTerminal,
    /// Cancellation landed before any provider effect was observed.
    CancelledTerminal,
    /// Terminal state is unknown; the reason is fixed text only.
    UnknownOutcome {
        /// Fixed unknown-outcome reason.
        reason: String,
    },
}

/// Fixed reason when cancellation follows a retryable failure.
const CANCELLED_AFTER_FAILURE_REASON: &str =
    "cancelled after retryable failure; provider effect unobserved";
/// Fixed reason when nothing terminal was observed.
const UNOBSERVED_REASON: &str = "terminal state unobserved";

/// Reconciles a cancellation request with the observed terminal state.
///
/// `failure` is the typed failure observed on the last attempt, if any. A
/// clean pre-effect cancellation yields `CancelledTerminal`; a cancellation
/// after a retryable failure, or any unobserved terminal without a failure,
/// yields an explicit `UnknownOutcome` carrying only fixed text.
#[must_use]
pub fn reconcile_terminal(
    cancel_requested: bool,
    observed: ObservedTerminal,
    failure: Option<RetryableFailure>,
) -> TerminalReconciliation {
    match observed {
        ObservedTerminal::Succeeded => TerminalReconciliation::Succeeded,
        ObservedTerminal::Failed => TerminalReconciliation::FailedTerminal,
        ObservedTerminal::Unobserved => {
            if cancel_requested {
                if failure.is_some() {
                    TerminalReconciliation::UnknownOutcome {
                        reason: CANCELLED_AFTER_FAILURE_REASON.to_owned(),
                    }
                } else {
                    TerminalReconciliation::CancelledTerminal
                }
            } else if let Some(typed) = failure {
                TerminalReconciliation::UnknownOutcome {
                    reason: typed.safe_diagnostic().to_owned(),
                }
            } else {
                TerminalReconciliation::UnknownOutcome {
                    reason: UNOBSERVED_REASON.to_owned(),
                }
            }
        }
    }
}

/// Deadline disposition carried by a physical attempt receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadlineDisposition {
    /// No deadline fired.
    None,
    /// The connect deadline fired.
    Connect,
    /// The TLS/header deadline fired.
    TlsHeaders,
    /// The first-byte deadline fired.
    FirstByte,
    /// The semantic-idle deadline fired.
    SemanticIdle,
    /// The overall-job deadline fired.
    OverallJob,
    /// The cleanup deadline fired.
    Cleanup,
}

impl DeadlineDisposition {
    /// Returns the stable disposition name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Connect => "connect",
            Self::TlsHeaders => "tls-headers",
            Self::FirstByte => "first-byte",
            Self::SemanticIdle => "semantic-idle",
            Self::OverallJob => "overall-job",
            Self::Cleanup => "cleanup",
        }
    }
}

/// Physical attempt receipt for one provider transport outcome.
///
/// Carries the attempt identity, the fired deadline disposition, the bounded
/// retry count, the safe public error, the restricted raw-error handle, and
/// the typed cancellation/terminal reconciliation state. Pure data: building
/// or validating a receipt takes no locks and performs no I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalAttemptReceipt {
    /// Attempt identity.
    pub attempt_id: String,
    /// Deadline disposition for the attempt.
    pub deadline: DeadlineDisposition,
    /// Attempts made, within `1..=max_attempts`.
    pub attempts_made: u32,
    /// Attempts the policy allowed.
    pub max_attempts: u32,
    /// Fixed safe public error message.
    pub safe_public_error: String,
    /// Restricted raw-error handle.
    pub restricted_raw_error: RestrictedRawErrorHandle,
    /// Typed reconciliation state.
    pub terminal: TerminalReconciliation,
}

impl PhysicalAttemptReceipt {
    /// Builds the receipt for a simulated first-byte timeout.
    ///
    /// Records the first-byte deadline disposition, the bounded retry count
    /// from `policy`, the fixed safe public error, the restricted raw-error
    /// handle for `raw_detail`, and the typed unknown-outcome reconciliation
    /// state. `attempts_made` clamps into `1..=max_attempts`.
    #[must_use]
    pub fn simulate_first_byte_timeout(
        policy: &RetryPolicy,
        attempt_id: &str,
        attempts_made: u32,
        raw_detail: &str,
    ) -> Self {
        let max_attempts = policy.max_attempts.max(1);
        let made = attempts_made.clamp(1, max_attempts);
        let (safe_public_error, restricted_raw_error) =
            split_transport_error(RetryableFailure::FirstByteTimeout, raw_detail);
        Self {
            attempt_id: attempt_id.to_owned(),
            deadline: DeadlineDisposition::FirstByte,
            attempts_made: made,
            max_attempts,
            safe_public_error,
            restricted_raw_error,
            terminal: reconcile_terminal(
                false,
                ObservedTerminal::Unobserved,
                Some(RetryableFailure::FirstByteTimeout),
            ),
        }
    }

    /// Rejects a blank identity, an inconsistent count, or a blank message.
    pub fn validate(&self) -> Result<(), TransportPolicyError> {
        if !is_nonblank_bounded(&self.attempt_id, MAX_ATTEMPT_ID_BYTES) {
            return Err(TransportPolicyError::InvalidReceipt("attempt_id"));
        }
        if self.max_attempts == 0
            || self.attempts_made == 0
            || self.attempts_made > self.max_attempts
        {
            return Err(TransportPolicyError::InvalidReceipt("attempts_made"));
        }
        if self.safe_public_error.trim().is_empty() {
            return Err(TransportPolicyError::InvalidReceipt("safe_public_error"));
        }
        Ok(())
    }
}

/// Revision/fence snapshot for one stateful route/session operation.
///
/// Discipline: snapshot under the lock, release the lock, run the external
/// call, reacquire, then [`validate_against`](Self::validate_against) before
/// committing results. The snapshot itself holds no guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSessionSnapshot {
    /// Revision observed at snapshot time.
    pub revision: u64,
    /// Fence observed at snapshot time.
    pub fence: StateFence,
}

/// Snapshots one revision/fence pair; callers release the lock right after.
#[must_use]
pub fn snapshot_route_session(revision: u64, fence: &StateFence) -> RouteSessionSnapshot {
    RouteSessionSnapshot {
        revision,
        fence: fence.clone(),
    }
}

impl RouteSessionSnapshot {
    /// Rejects a commit when the live revision or fence moved on.
    pub fn validate_against(
        &self,
        current_revision: u64,
        current_fence: &StateFence,
    ) -> Result<(), TransportPolicyError> {
        if self.revision != current_revision || self.fence != *current_fence {
            return Err(TransportPolicyError::StaleSnapshot);
        }
        Ok(())
    }
}

/// One TTL/affinity entry offered to a cleanup run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffinityEntry {
    /// Entry key.
    pub key: String,
    /// Unix-millisecond expiry.
    pub expires_at_unix_ms: u64,
}

/// Observable receipt for one eviction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvictionReceipt {
    /// Evicted entry key.
    pub key: String,
    /// Fixed eviction-policy reason.
    pub reason: String,
    /// Unix-millisecond observation time.
    pub observed_at_unix_ms: u64,
}

/// Supervision health of a cleanup job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupHealth {
    /// The job is available for supervised runs.
    Healthy,
    /// Cancellation was requested; runs stop early.
    Cancelled,
}

/// Supervised bounded TTL/affinity cleanup job.
///
/// Evicts at most `max_evictions_per_run` expired entries per run, stops
/// early once cancelled, and emits one [`EvictionReceipt`] per eviction so
/// the eviction policy stays observable. Supervision stays with the daemon
/// runtime through `cancel`, `health`, and `completed_runs`; this job keeps
/// no thread, no timer, and no detached task.
#[derive(Debug)]
pub struct AffinityCleanupJob {
    max_evictions_per_run: usize,
    cancelled: AtomicBool,
    completed_runs: AtomicU64,
}

impl AffinityCleanupJob {
    /// Builds a job evicting at most `max_evictions_per_run` entries per run.
    pub fn new(max_evictions_per_run: usize) -> Result<Self, TransportPolicyError> {
        if max_evictions_per_run == 0 {
            return Err(TransportPolicyError::InvalidReceipt(
                "max_evictions_per_run",
            ));
        }
        Ok(Self {
            max_evictions_per_run,
            cancelled: AtomicBool::new(false),
            completed_runs: AtomicU64::new(0),
        })
    }

    /// Requests cancellation; in-flight runs stop early.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Returns true once cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Returns the supervision health of the job.
    #[must_use]
    pub fn health(&self) -> CleanupHealth {
        if self.is_cancelled() {
            CleanupHealth::Cancelled
        } else {
            CleanupHealth::Healthy
        }
    }

    /// Returns the count of completed runs.
    #[must_use]
    pub fn completed_runs(&self) -> u64 {
        self.completed_runs.load(Ordering::Relaxed)
    }

    /// Returns the per-run eviction cap.
    #[must_use]
    pub const fn max_evictions_per_run(&self) -> usize {
        self.max_evictions_per_run
    }

    /// Evicts expired entries, bounded, cancellable, and receipted.
    ///
    /// Entries with `expires_at_unix_ms` at or before `now_unix_ms` evict in
    /// slice order until the per-run cap or a cancellation request. Every
    /// run counts once in `completed_runs`, including an early-stopped run.
    #[must_use]
    pub fn run_once(&self, entries: &[AffinityEntry], now_unix_ms: u64) -> Vec<EvictionReceipt> {
        let mut receipts = Vec::new();
        for entry in entries {
            if self.is_cancelled() || receipts.len() >= self.max_evictions_per_run {
                break;
            }
            if entry.expires_at_unix_ms <= now_unix_ms {
                receipts.push(EvictionReceipt {
                    key: entry.key.clone(),
                    reason: EVICTION_REASON_TTL_EXPIRED.to_owned(),
                    observed_at_unix_ms: now_unix_ms,
                });
            }
        }
        self.completed_runs.fetch_add(1, Ordering::Relaxed);
        receipts
    }
}

/// Authenticated loopback/IPC default for local provider servers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalIpcPolicy {
    /// True only when the local channel requires authentication.
    pub authenticated: bool,
}

impl LocalIpcPolicy {
    /// Returns the authenticated default.
    #[must_use]
    pub const fn authenticated_default() -> Self {
        Self {
            authenticated: true,
        }
    }

    /// Rejects an unauthenticated local channel.
    pub fn validate(&self) -> Result<(), TransportPolicyError> {
        if self.authenticated {
            Ok(())
        } else {
            Err(TransportPolicyError::LocalIpcUnauthenticated)
        }
    }
}
