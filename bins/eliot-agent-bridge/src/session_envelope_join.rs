//! Live-attach session-envelope join (M2; #1942/#19).
//!
//! Contract decisions (normative grounding):
//!
//! - `recipient_id` is defined as the owner-supplied recipient route
//!   identity ([`ReactiveContextRecipient::route`]: "Route fingerprint or
//!   route identity"). `session_id` and `runtime_id` travel in their own
//!   snapshot fields; no field is ever inferred from another.
//! - Session membership is proven by joining producer facts against the LIVE
//!   attach session and fence (`BridgeRunner::live_reactive_session` and the
//!   live state fence). A first-bind claim agreeing with itself proves
//!   nothing; only the live attach join admits.
//! - Generation precedence: the kernel receipt `runtime_generation` is
//!   authoritative over recipient-observed generations (a recipient newer
//!   than the kernel receipt refuses as skew); the maximum `queue_generation`
//!   per session wins; `host_generation` is a required owner-issued
//!   parameter (Host/SCM cutover owner per I02-10 `host_generation`) that
//!   fails closed when zero — never derived from epoch sequences.
//! - Fence ownership split: attempt `StateFence` values compare exactly
//!   against the live fence; delivery `RecordFence` values are trusted via
//!   Host-journal commitment plus session binding (never converted).
//!
//! The winning delivery's queue [`ReactiveContextStage`] is carried into the
//! output so terminal stages stay visible downstream instead of being
//! dropped by terminal-including scans.

use eliot_contracts::{ResourceGeneration, StateFence};
use eliot_protocol::{ReactiveContextRecipient, ReactiveContextStage};

/// Attempt-side join fact (view over O1 `SessionBoundAttemptFacts`).
#[derive(Clone, Copy, Debug)]
pub struct AttemptJoinFact<'a> {
    /// Session admitted at the provider-execution bind.
    pub session: &'a str,
    /// Fence admitted with the attempt.
    pub fence: &'a StateFence,
    /// Live attempt identity.
    pub attempt_id: &'a str,
    /// Task the attempt was admitted for.
    pub task_id: &'a str,
}

/// Delivery-side join fact (view over O1 `AdmittedDeliveryFacts`).
#[derive(Clone, Copy, Debug)]
pub struct DeliveryJoinFact<'a> {
    /// Recipient session the payload was admitted for.
    pub session: &'a str,
    /// Exact admitted recipient (session, runtime identity, runtime
    /// generation, route).
    pub recipient: &'a ReactiveContextRecipient,
    /// Opaque runtime identity from the admitted recipient.
    pub runtime_id: &'a str,
    /// Journal queue generation of the retained entry.
    pub queue_generation: u64,
    /// Last accepted queue phase, terminal phases included.
    pub stage: ReactiveContextStage,
}

/// Session envelope joined against the live attach.
#[derive(Clone, Debug, PartialEq)]
pub struct JoinedSessionEnvelope {
    /// Live attach session every fact agreed with.
    pub session: String,
    /// Owner-supplied recipient route identity (contract decision).
    pub recipient_id: String,
    /// Opaque runtime identity of the winning delivery.
    pub runtime_id: String,
    /// Authoritative kernel receipt runtime generation.
    pub runtime_generation: ResourceGeneration,
    /// Owner-issued Host cutover generation.
    pub host_generation: ResourceGeneration,
    /// Maximum queue generation observed for the session.
    pub queue_generation: u64,
    /// Queue phase of the winning delivery, terminal phases included.
    pub stage: ReactiveContextStage,
    /// Bound live attempt, when exactly one agrees.
    pub attempt_id: Option<String>,
    /// Task of the bound attempt, when exactly one agrees.
    pub task_id: Option<String>,
}

/// Fail-closed join errors. Each names the exact disagreeing fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionJoinError {
    /// No deliveries were supplied at all.
    NoDeliveries,
    /// No delivery agrees with the live attach session.
    SessionMismatch,
    /// A live-session attempt carries a non-live fence.
    FenceMismatch,
    /// The admitted recipient route is empty.
    EmptyRoute,
    /// The admitted runtime identity is empty.
    EmptyRuntime,
    /// An owner-issued generation is zero.
    ZeroGeneration,
    /// A recipient observes a generation newer than the kernel receipt.
    GenerationSkew,
}

impl core::fmt::Display for SessionJoinError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoDeliveries => {
                write!(formatter, "session join refused: no delivery facts supplied")
            }
            Self::SessionMismatch => write!(
                formatter,
                "session join refused: no delivery fact for live session"
            ),
            Self::FenceMismatch => write!(
                formatter,
                "session join refused: attempt fence disagrees with live fence"
            ),
            Self::EmptyRoute => write!(
                formatter,
                "session join refused: admitted recipient route is empty"
            ),
            Self::EmptyRuntime => write!(
                formatter,
                "session join refused: admitted runtime identity is empty"
            ),
            Self::ZeroGeneration => {
                write!(formatter, "session join refused: owner generation is zero")
            }
            Self::GenerationSkew => write!(
                formatter,
                "session join refused: recipient generation is newer than the kernel receipt"
            ),
        }
    }
}

impl std::error::Error for SessionJoinError {}

/// Derives the contract recipient identity from an admitted recipient.
///
/// The recipient route is the endpoint identity; session and runtime travel
/// separately and are never mixed into this value.
pub fn derive_recipient_id(
    recipient: &ReactiveContextRecipient,
) -> Result<&str, SessionJoinError> {
    if recipient.route.is_empty() {
        return Err(SessionJoinError::EmptyRoute);
    }
    Ok(recipient.route.as_str())
}

/// Joins producer facts against the live attach session and fence.
///
/// Order: session agreement (deliveries, then attempts) → fence agreement
/// (attempts) → recipient derivation → generation precedence (kernel wins,
/// skew refuses) → owner-issued host generation gate → winning delivery
/// (maximum queue generation) → joined envelope. Anything else withholds.
#[allow(clippy::too_many_arguments)]
pub fn join_live_session_envelope(
    live_session: &str,
    live_fence: &StateFence,
    kernel_runtime_generation: &ResourceGeneration,
    host_generation: &ResourceGeneration,
    attempts: &[AttemptJoinFact<'_>],
    deliveries: &[DeliveryJoinFact<'_>],
) -> Result<JoinedSessionEnvelope, SessionJoinError> {
    if deliveries.is_empty() {
        return Err(SessionJoinError::NoDeliveries);
    }
    if kernel_runtime_generation.value() == 0 || host_generation.value() == 0 {
        return Err(SessionJoinError::ZeroGeneration);
    }
    let mut winner: Option<&DeliveryJoinFact<'_>> = None;
    for delivery in deliveries {
        if delivery.session != live_session {
            continue;
        }
        if delivery.runtime_id.is_empty() {
            return Err(SessionJoinError::EmptyRuntime);
        }
        derive_recipient_id(delivery.recipient)?;
        if delivery.recipient.runtime_generation.value() > kernel_runtime_generation.value() {
            return Err(SessionJoinError::GenerationSkew);
        }
        winner = match winner {
            Some(current) if current.queue_generation >= delivery.queue_generation => Some(current),
            _ => Some(delivery),
        };
    }
    let winner = winner.ok_or(SessionJoinError::SessionMismatch)?;
    let mut attempt_id = None;
    let mut task_id = None;
    let mut bound = 0;
    for attempt in attempts {
        if attempt.session != live_session {
            continue;
        }
        if attempt.fence != live_fence {
            return Err(SessionJoinError::FenceMismatch);
        }
        bound += 1;
        attempt_id = Some(attempt.attempt_id.to_owned());
        task_id = Some(attempt.task_id.to_owned());
    }
    if bound != 1 {
        attempt_id = None;
        task_id = None;
    }
    Ok(JoinedSessionEnvelope {
        session: live_session.to_owned(),
        recipient_id: winner.recipient.route.clone(),
        runtime_id: winner.runtime_id.to_owned(),
        runtime_generation: kernel_runtime_generation.clone(),
        host_generation: host_generation.clone(),
        queue_generation: winner.queue_generation,
        stage: winner.stage,
        attempt_id,
        task_id,
    })
}
