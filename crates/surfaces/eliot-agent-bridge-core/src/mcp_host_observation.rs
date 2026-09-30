//! Competent host-side producer for MCP invocation correlation.
//!
//! Issue #2899, item 4: the stdio facade cannot observe host/UI terminal
//! state from inside its own process. This adapter normalizes one event from
//! the owning Agent Bridge journal into a typed [`HostTerminalObservation`],
//! binding host integration identity, installation/session/process
//! generation, correlation identity, route fingerprint, terminal state, event
//! identity/sequence/cursor, observed time, and the applicable deadline.
//!
//! The adapter verifies everything verifiable in the envelope (validity,
//! terminal kind, invocation scope, route digest) and joins the *event's own*
//! observed session against the *owner's live* current session, so a stale or
//! foreign generation, a duplicated or reordered event, an unattributable
//! lineage, and an event that names no invocation each close nothing current.
//! The observed side is never taken from the joining caller's keys, and the
//! expected side is never taken from them either: both the live generation and
//! the expected route digest come from the event owner's own attach binding and
//! its own observed route fingerprint ([`HostOwnerBinding`]). Comparing two
//! caller-supplied fields, or recomputing a fresh digest over what the join
//! already holds, would only prove that the caller agrees with itself.
//! Correlation attribution rides the owner's journal session binding: the owner
//! nominates the candidate event from its live journal and the join verifies it
//! there verbatim (see `crate::mcp_bridge_join`). UI-only screenshots and free
//! text are not machine authority and never enter the observation.
//!
//! The one thing a join cannot manufacture is a link between a host event and
//! one specific MCP request. Route, session, and generation are shared by every
//! correlation on that route, so they can narrow a candidate set but never
//! identify a request; only the candidate's own invocation-scoped observation
//! can, and a terminal payload does not carry one. An event that names no
//! invocation is therefore refused outright rather than being allowed to close
//! whichever correlation happens to be pending.

use crate::{
    HostEventEnvelope, HostEventKind, NormalizedHostEventPayload, ProviderObservationLineage,
};

use crate::mcp_correlation::{
    HostObservationEvidence, HostTerminalObservation, HostTerminalState, sha256_hex,
};

/// Exact join keys the event owner attests for one candidate host event.
///
/// The keys carry only the *expected* side of the join, and even that is
/// restricted to what the owner itself attests about the correlation: the host
/// integration identity and an applicable deadline. There is deliberately no
/// observed-generation field and no expected-route field here: a pair of
/// caller-supplied generations or route digests can only prove that the caller
/// agrees with itself, and a fresh digest recomputed over what the join already
/// holds is not a recorded value. Both of those are read from the event owner
/// itself ([`HostOwnerBinding`]), and the observed side is derived from the
/// candidate's own owner-validated lineage.
///
/// There is deliberately no correlation identity here either. The digest that
/// names a correlation is the one the correlation itself recorded, so it is
/// passed to [`normalize_terminal_observation`] as that recorded value rather
/// than as a key the joining caller restates: a key would only let the caller
/// nominate a correlation, never prove the event belongs to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEventJoinKeys {
    /// Host integration identity that produced the observation.
    pub integration_id: String,
    /// Applicable observation deadline admitted by the owner, when one exists.
    pub deadline_unix_ms: Option<u64>,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostOwnerBinding {
    /// Installation identity the owner's live attach binding names.
    pub installation_id: String,
    /// Session the owner's live attach binding names.
    pub session_id: String,
    /// Authority generation the owner's live attach binding names.
    pub activation_generation: String,
    /// Digest of the route fingerprint the owner itself observed.
    pub route_digest: String,
}

/// Why a candidate host event was rejected for correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostObservationReject {
    /// The envelope failed structural validation.
    InvalidEnvelope(String),
    /// The event kind attests no terminal invocation state.
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
    /// The event's own owner-validated observation names no single invocation,
    /// so it cannot be attributed to one exact correlation.
    ///
    /// This is a refusal, never a degraded outcome. A terminal fact scoped to a
    /// provider turn or step is not a fact about any one MCP request, and
    /// attributing it to whichever correlation happens to be pending would
    /// invent a host completion that was never observed for that request.
    InvocationScopeUnattributable,
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
                    "host event kind {kind} attests no terminal invocation state"
                )
            }
            Self::RouteMismatch { expected, observed } => write!(
                formatter,
                "host event route mismatch: expected {expected}, observed {observed}"
            ),
            Self::SessionLineageUnattributable => formatter.write_str(
                "host event lineage attributes no session; it closes no current correlation",
            ),
            Self::InvocationScopeUnattributable => formatter.write_str(
                "host event names no single invocation; it closes no current correlation",
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

/// Reads the invocation scope the candidate's own observation carries.
///
/// Only the two tool-scoped payloads name one exact invocation, through the
/// adapter-minted `invocation_ref`. Every other payload — including
/// `ProviderTerminalObserved`, which is what a terminal kind actually carries —
/// names something coarser than one invocation, and is deliberately reported as
/// carrying no invocation scope at all.
///
/// In particular `ProviderTerminalObservation::terminal_ref` is NOT an
/// invocation scope and is never read as one: the `OpenCode` producer emits the
/// constant `"opencode:step-finish-stop"` for every step-finish event, and the
/// Codex producer emits the bound turn, which spans many invocations. Treating
/// either as an invocation identity would compare one shared constant against
/// every correlation, which is the same self-agreement defect as comparing a
/// record's digest to itself — only with a false positive instead of a vacuous
/// pass.
fn invocation_scope(event: &HostEventEnvelope) -> Option<&str> {
    let normalized = event.normalized().ok()?;
    match &normalized.payload {
        NormalizedHostEventPayload::ToolInvocation(observation) => {
            Some(observation.invocation_ref.as_str())
        }
        NormalizedHostEventPayload::ToolOutcome(observation) => {
            Some(observation.invocation_ref.as_str())
        }
        _ => None,
    }
}

/// Normalizes one owner-nominated host event into a terminal observation.
///
/// Verifies envelope validity, terminal kind, the exact route digest, and that
/// the event's own owner-validated observation names one exact invocation, then
/// joins the event's *own* observed generation against the owner's live current
/// session: the observed side is read from the closed, versioned normalized
/// observation the envelope carries (never from caller input and never from the
/// wire's generic JSON), the expected side is the owner's own live attach binding
/// and its own observed route fingerprint ([`HostOwnerBinding`]). The evidence
/// records that owner-sourced generation verbatim, so a correlation never
/// carries a generation the join caller asserted, and it records the recorded
/// correlation digest passed in by the join rather than a key the caller
/// restated. Non-terminal kinds, events that name no invocation, foreign routes,
/// unattributable lineage, and stale generations are rejected: missing or
/// mismatched telemetry is never relabeled as a host fault.
///
/// `correlation_digest` is the digest the correlation itself recorded. It
/// reaches the evidence because the join already established that this event
/// belongs to that correlation; it is never an input that could establish it.
pub fn normalize_terminal_observation(
    event: &HostEventEnvelope,
    keys: &HostEventJoinKeys,
    owner: &HostOwnerBinding,
    correlation_digest: &str,
) -> Result<HostTerminalObservation, HostObservationReject> {
    event
        .validate()
        .map_err(|error| HostObservationReject::InvalidEnvelope(error.to_string()))?;
    let state = match event.kind {
        HostEventKind::Completed => HostTerminalState::InvocationCompleted,
        HostEventKind::Error | HostEventKind::Failed => HostTerminalState::InvocationError,
        other => {
            return Err(HostObservationReject::NonTerminalKind(format!("{other:?}")));
        }
    };
    // A terminal host fact must name the invocation it closes. The candidate's
    // own normalized payload is the only place that identity can come from, and
    // a terminal payload carries none: the invocation-scoped payloads are
    // `ToolInvocation`/`ToolOutcome`, whose kinds are `ToolCall`/`ToolResult`,
    // not `Completed`/`Error`/`Failed`. Route and session are not a substitute
    // — every correlation on the route shares both, so accepting on them is
    // exactly the false attribution this gate exists to prevent. So a terminal
    // event that names no invocation closes no correlation, and the correlation
    // stays pending.
    if invocation_scope(event).is_none() {
        return Err(HostObservationReject::InvocationScopeUnattributable);
    }
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
            correlation_digest: correlation_digest.to_owned(),
            route_digest,
            event_id: event.event_id.as_str().to_owned(),
            sequence: event.sequence,
            cursor: event.cursor.as_str().to_owned(),
            event_digest: sha256_hex(event_json.as_bytes()),
            observed_at: event.observed_at.clone(),
            deadline_unix_ms: keys.deadline_unix_ms,
        }),
    })
}

/// Replay disposition of a candidate host event against prior evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostEventReplay {
    /// Same event identity with identical content: idempotent, safe to accept.
    ExactDuplicate,
    /// Different event identity: a new observation, not a replay.
    Distinct,
}

/// Same event identity observed with changed content: a hard conflict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayConflict {
    /// Conflicting event identity.
    pub event_id: String,
    /// Digest of the previously accepted content.
    pub prior_digest: String,
    /// Digest of the candidate content.
    pub candidate_digest: String,
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
pub fn check_event_replay(
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
