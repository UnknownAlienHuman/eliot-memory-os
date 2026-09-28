//! Competent host-side producer for MCP invocation correlation.
//!
//! Issue #2899, item 4: the stdio facade cannot observe host/UI terminal
//! state from inside its own process. This adapter normalizes one event from
//! the owning Agent Bridge journal into a typed [`HostTerminalObservation`],
//! binding host integration identity, installation/session/process
//! generation, correlation identity, the event's own route admission
//! reference, terminal state, event identity/sequence/cursor, observed time,
//! and the applicable deadline.
//!
//! The adapter verifies everything verifiable in the envelope (validity,
//! terminal kind, route digest) and joins the *event's own* observed session
//! against the *owner's live* current session, so a stale or foreign
//! generation, a duplicated or reordered event, and an unattributable lineage
//! each close nothing current. The observed side is never taken from the
//! joining caller's keys, and the expected side is never taken from them
//! either: both the live generation and the expected route digest come from the
//! event owner's own attach binding and its own observed route fingerprint
//! ([`HostOwnerBinding`]). Comparing two caller-supplied fields, or
//! recomputing a fresh digest over what the join already holds, would only
//! prove that the caller agrees with itself. Correlation attribution rides the
//! owner's journal session binding: the owner nominates the candidate event
//! from its live journal and the join verifies it there verbatim (see
//! `super::bridge_join`). UI-only screenshots and free text are not machine
//! authority and never enter the observation.

use eliot_agent_bridge_core::{
    NormalizedHostEventEnvelope, NormalizedHostEventPayload, ProviderObservationLineage,
    ProviderTerminalStatus,
};

use super::correlation::{
    HostObservationEvidence, HostTerminalObservation, HostTerminalState, sha256_hex,
};

/// Exact join keys the event owner attests for one candidate host event.
///
/// The keys carry only the *expected* side of the join, and even that is
/// restricted to what the owner itself attests about the correlation: the
/// host integration identity and the correlation digest the owner joined the
/// event to, plus an applicable deadline. There is deliberately no
/// observed-generation field and no expected-route field here: a pair of
/// caller-supplied generations or route digests can only prove that the caller
/// agrees with itself, and a fresh digest recomputed over what the join already
/// holds is not a recorded value. Both of those are read from the event owner
/// itself ([`HostOwnerBinding`]), and the observed side is derived from the
/// candidate's own owner-validated lineage.
#[allow(
    dead_code,
    reason = "owner seam: attested only by the bridge-owning join caller (#2899)"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostEventJoinKeys {
    /// Host integration identity that produced the observation.
    pub(crate) integration_id: String,
    /// Owner-attested correlation digest the event is joined to.
    pub(crate) correlation_digest: String,
    /// Applicable observation deadline admitted by the owner, when one exists.
    pub(crate) deadline_unix_ms: Option<u64>,
}

/// Live generation the event owner itself states for the joined route.
///
/// Every field is read from the owner's own live attach binding and its own
/// journal, never from the joining caller. This is the *expected* side of the
/// generation join; the *observed* side comes from the candidate event's own
/// owner-validated lineage, and the two are compared as values. An event whose
/// own session is not the owner's live session is stale and closes nothing; a
/// lineage that attributes no session is unattributable, which is a different
/// outcome and is never relabeled as a host fault.
#[allow(
    dead_code,
    reason = "owner seam: read by the bridge join from the live owner attach binding (#2899)"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostOwnerBinding {
    /// Installation identity the owner's live attach binding names.
    pub(crate) installation_id: String,
    /// Session the owner's live attach binding names.
    pub(crate) session_id: String,
    /// Authority generation the owner's live attach binding names.
    pub(crate) activation_generation: String,
    /// Digest of the route fingerprint the owner itself observed.
    pub(crate) route_digest: String,
}

/// Why a candidate host event was rejected for correlation.
#[allow(
    dead_code,
    reason = "owner seam: raised only by the bridge join's normalization path (#2899)"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HostObservationReject {
    /// The envelope failed structural validation.
    InvalidEnvelope(String),
    /// The event payload attests no terminal invocation state.
    NonTerminalKind(String),
    /// The event arrived on a different route than the correlation expects.
    RouteMismatch {
        /// Expected route digest from the join keys.
        expected: String,
        /// Observed route digest from the event.
        observed: String,
    },
    /// The event's own owner-validated lineage attributes no session, so no
    /// generation can be compared for it. Unattributable, not a host fault.
    SessionLineageUnattributable,
    /// The event's own session is not the owner's current session; a rotated or
    /// restarted session must not relabel an old observation as current.
    StaleGeneration {
        /// Session the event's own lineage names.
        observed: String,
        /// Session the owner's live attach binding names.
        current: String,
    },
}

impl std::fmt::Display for HostObservationReject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEnvelope(reason) => {
                write!(formatter, "host event envelope is invalid: {reason}")
            }
            Self::NonTerminalKind(kind) => {
                write!(
                    formatter,
                    "host event payload {kind} attests no terminal invocation state"
                )
            }
            Self::RouteMismatch { expected, observed } => write!(
                formatter,
                "host event route mismatch: expected {expected}, observed {observed}"
            ),
            Self::SessionLineageUnattributable => formatter.write_str(
                "host event lineage attributes no session; it closes no current correlation",
            ),
            Self::StaleGeneration { observed, current } => write!(
                formatter,
                "host event session {observed} is not the owner current session {current}; \
                 it closes no current correlation"
            ),
        }
    }
}

impl std::error::Error for HostObservationReject {}

/// Normalizes one owner-nominated host event into a terminal observation.
///
/// Verifies envelope validity, the terminal payload class, and the exact route
/// digest, then joins the event's *own* observed session against the owner's
/// live current session: the observed side is read from the closed, versioned
/// normalized observation the envelope carries (never from caller input and
/// never from the wire's generic JSON), the expected side is the owner's own
/// live attach binding and its own observed route fingerprint
/// ([`HostOwnerBinding`]). The evidence records that owner-sourced session
/// verbatim, so a correlation never carries a session the join caller asserted.
/// Non-terminal payloads, foreign routes, unattributable lineage, and stale
/// sessions are rejected: missing or mismatched telemetry is never relabeled as
/// a host fault.
#[allow(
    dead_code,
    reason = "owner seam: invoked by the bridge-owning process with live journal events; the facade observes no host events itself (#2899)"
)]
pub(crate) fn normalize_terminal_observation(
    event: &NormalizedHostEventEnvelope,
    keys: &HostEventJoinKeys,
    owner: &HostOwnerBinding,
) -> Result<HostTerminalObservation, HostObservationReject> {
    event
        .validate_as_session_observation()
        .map_err(|error| HostObservationReject::InvalidEnvelope(error.to_string()))?;
    let state = match &event.payload {
        NormalizedHostEventPayload::ProviderTerminalObserved(terminal) => match terminal.status {
            ProviderTerminalStatus::CompletedObserved => HostTerminalState::InvocationCompleted,
            ProviderTerminalStatus::FailedObserved | ProviderTerminalStatus::CancelledObserved => {
                HostTerminalState::InvocationError
            }
        },
        other => {
            return Err(HostObservationReject::NonTerminalKind(format!(
                "{}",
                other.payload_type_tag()
            )));
        }
    };
    let route_json = event
        .route
        .canonical_json()
        .map_err(|error| HostObservationReject::InvalidEnvelope(error.to_string()))?;
    let route_digest = sha256_hex(route_json.as_bytes());
    if route_digest != owner.route_digest {
        return Err(HostObservationReject::RouteMismatch {
            expected: owner.route_digest.clone(),
            observed: route_digest,
        });
    }
    // The observed generation side comes from the closed normalized observation
    // the envelope carries — never from the joining caller's keys and never
    // from the wire's generic JSON. A lineage that attributes no session is
    // *unattributable*, which is a different outcome from a *stale* generation
    // and is never relabeled as a host fault.
    let observed_session =
        event
            .normalized()
            .ok()
            .and_then(|normalized| match &normalized.lineage {
                ProviderObservationLineage::SessionObservation(observation) => {
                    observation.session_id.as_ref()
                }
                ProviderObservationLineage::ExecutionUnitObservation(observation) => {
                    observation.binding.session_id.as_ref()
                }
            });
    let Some(observed_session) = observed_session else {
        return Err(HostObservationReject::SessionLineageUnattributable);
    };
    if observed_session.as_str() != owner.session_id {
        return Err(HostObservationReject::StaleGeneration {
            observed: observed_session.as_str().to_owned(),
            current: owner.session_id.clone(),
        });
    }
    let event_json = serde_json::to_string(event)
        .map_err(|error| HostObservationReject::InvalidEnvelope(error.to_string()))?;
    Ok(HostTerminalObservation::Observed {
        state,
        evidence: Box::new(HostObservationEvidence {
            integration_id: keys.integration_id.clone(),
            installation_id: owner.installation_id.clone(),
            session_generation: owner.session_id.clone(),
            process_generation: owner.activation_generation.clone(),
            correlation_digest: keys.correlation_digest.clone(),
            route_digest,
            event_id: event.event_id.as_str().to_owned(),
            sequence: event.sequence,
            cursor: event.cursor.as_str().to_owned(),
            event_digest: sha256_hex(event_json.as_bytes()),
            observed_at: event.observed_at,
            deadline_unix_ms: keys.deadline_unix_ms,
        }),
    })
}

/// Replay disposition of a candidate host event against prior evidence.
#[allow(
    dead_code,
    reason = "owner seam: returned only by the bridge join's replay check (#2899)"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostEventReplay {
    /// Same event identity with identical content: idempotent, safe to accept.
    ExactDuplicate,
    /// Different event identity: a new observation, not a replay.
    Distinct,
}

/// Same event identity observed with changed content: a hard conflict.
#[allow(
    dead_code,
    reason = "owner seam: raised only by the bridge join's replay check (#2899)"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplayConflict {
    /// Conflicting event identity.
    pub(crate) event_id: String,
    /// Digest of the previously accepted content.
    pub(crate) prior_digest: String,
    /// Digest of the candidate content.
    pub(crate) candidate_digest: String,
}

impl std::fmt::Display for ReplayConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "host event {} changed content: prior {} candidate {}",
            self.event_id, self.prior_digest, self.candidate_digest
        )
    }
}

impl std::error::Error for ReplayConflict {}

/// Checks a candidate host event against previously accepted evidence.
///
/// Exact replay is idempotent; same event identity with changed content
/// conflicts and must never silently supersede the prior observation.
#[allow(
    dead_code,
    reason = "owner seam: invoked by the bridge join when reconciling nominated host events (#2899)"
)]
pub(crate) fn check_event_replay(
    prior: &HostObservationEvidence,
    candidate: &HostObservationEvidence,
) -> Result<HostEventReplay, ReplayConflict> {
    if prior.event_id != candidate.event_id {
        return Ok(HostEventReplay::Distinct);
    }
    if prior == candidate {
        return Ok(HostEventReplay::ExactDuplicate);
    }
    Err(ReplayConflict {
        event_id: prior.event_id.clone(),
        prior_digest: prior.event_digest.clone(),
        candidate_digest: candidate.event_digest.clone(),
    })
}
