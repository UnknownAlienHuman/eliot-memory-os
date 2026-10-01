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
//! can. That is the closed `ToolOutcome` payload: the host's own per-invocation
//! terminal fact, carrying the invocation reference the host integration minted
//! for the invocation it made and the classified outcome it observed. The
//! terminal-but-turn-scoped payloads (`ProviderTerminalObserved`, `Error`)
//! name something coarser than one invocation and are refused outright rather
//! than being allowed to close whichever correlation happens to be pending.
//!
//! Attribution is then an exact value comparison against the correlation's own
//! recorded request identity ([`RecordedInvocation`]): the candidate's minted
//! invocation reference must equal the MCP request identity the serving
//! boundary itself recorded, and a recorded tool name must match the candidate's
//! own tool name. This is what binds "MCP request/correlation identity" (issue
//! #2899 item 4) to the event. A host integration that mints its scope from
//! anything else closes nothing, which is the intended fail-closed direction:
//! the correlation stays pending rather than borrowing a foreign observation.
//!
//! The correlation's OWNER-ISSUED operation values — the owner's operation
//! handle, the owner's commitment to the request's identity, and the owner's
//! effect class (see `crate::mcp_correlation::CorrelationIdentity`) — are
//! deliberately neither read from nor matched against a host event here. A host
//! integration observes an invocation, not a canonical operation: it never sees
//! the owner's `operation_id`, its idempotency key, its bound state fence, or
//! its effect class, so a host event could only ever restate them by accident or
//! by copying. Those three values are therefore owner-side only, bound from the
//! owner's own receipt by
//! `crate::mcp_correlation::OwnerValidatedOperationBinding::from_owner_receipt`
//! and verified against the correlation's own record by
//! `crate::mcp_correlation::identity_commits_to_operation`; this adapter attests
//! host terminal state and nothing about canonical operation identity.

use crate::host_event::ToolOutcomeClass;
use crate::{HostEventEnvelope, NormalizedHostEventPayload, ProviderObservationLineage};

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
/// names a correlation, the exact request identity that names its invocation,
/// and the generation it was emitted under are all recorded by the correlation
/// itself, so they reach [`normalize_terminal_observation`] as that recorded
/// [`RecordedInvocation`] rather than as keys the joining caller restates: a key
/// would only let the caller nominate a correlation, never prove the event
/// belongs to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEventJoinKeys {
    /// Host integration identity that produced the observation.
    pub integration_id: String,
    /// Applicable observation deadline admitted by the owner, when one exists.
    pub deadline_unix_ms: Option<u64>,
}

/// The exact invocation one correlation recorded for itself.
///
/// Read back from the correlation's own immutable
/// [`EliotEmissionObservation`](crate::mcp_correlation::EliotEmissionObservation)
/// identity, never from the joining caller, so no caller can nominate the
/// invocation an event is attributed to. Every field is a fact the serving
/// stdio boundary measured about the request it received: the digest names the
/// correlation, and the request identity and tool name are what the host must
/// have named when it minted the invocation scope it observes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedInvocation {
    /// Digest the correlation itself recorded.
    pub correlation_digest: String,
    /// Exact MCP request identity the serving boundary recorded.
    pub request_id: String,
    /// Exact tool name the serving boundary recorded, when the call named one.
    pub tool_name: Option<String>,
    /// Session generation the serving boundary recorded, when it recorded one.
    pub session_id: Option<String>,
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
    /// The host classified the per-invocation outcome as unknown, so it attests
    /// no terminal state. Never read as success (I7.23: missing coverage is
    /// `TAINTED/UNKNOWN`, never a self-reported PASS).
    UnclassifiedInvocationOutcome,
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
    /// The event's own invocation reference names a different MCP request than
    /// the one this correlation recorded. A foreign or duplicated host
    /// invocation closes nothing.
    InvocationMismatch {
        /// Exact MCP request identity the correlation recorded.
        expected: String,
        /// Invocation reference the host's own observation minted.
        observed: String,
    },
    /// The event's own tool name is not the tool this correlation recorded.
    ToolMismatch {
        /// Exact tool name the correlation recorded.
        expected: String,
        /// Tool name the host's own observation names.
        observed: String,
    },
    /// The event's own session is not the session this correlation recorded,
    /// so a rotated or restarted generation must not relabel an old invocation
    /// as current.
    RecordedGenerationMismatch {
        /// Session the event's own lineage names.
        observed: String,
        /// Session the correlation recorded for the invocation it emitted.
        recorded: String,
    },
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
            Self::UnclassifiedInvocationOutcome => formatter.write_str(
                "host classified the invocation outcome as unknown; it attests no terminal state",
            ),
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
            Self::InvocationMismatch { expected, observed } => write!(
                formatter,
                "host event names invocation {observed}, not the correlated request \
                 {expected}; it closes nothing current"
            ),
            Self::ToolMismatch { expected, observed } => write!(
                formatter,
                "host event names tool {observed}, not the correlated tool {expected}; \
                 it closes nothing current"
            ),
            Self::RecordedGenerationMismatch { observed, recorded } => write!(
                formatter,
                "host event session {observed} is not the session {recorded} this \
                 invocation was recorded under; it closes nothing current"
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

/// One terminal fact read out of the candidate's own invocation-scoped
/// observation: the host's classified outcome for exactly one invocation, plus
/// the invocation scope and tool name the host's own integration minted.
struct InvocationTerminalFact<'a> {
    /// Terminal state the host's classified outcome attests.
    state: HostTerminalState,
    /// Invocation reference the host's integration minted for the invocation.
    invocation_ref: &'a str,
    /// Tool name the host's own observation names.
    tool_name: &'a str,
}

/// Reads the invocation-scoped terminal fact the candidate's own payload
/// carries, and refuses everything else.
///
/// Only the closed tool-scoped payloads name one exact invocation, through the
/// adapter-minted `invocation_ref`. Of those two only `ToolOutcome` is terminal:
/// `ToolInvocation` observes the host *starting* an invocation and says nothing
/// about how it ended. Every other payload — including
/// `ProviderTerminalObserved`, which is what a turn- or step-scoped terminal
/// kind carries — names something coarser than one invocation, and is
/// deliberately reported as carrying no invocation scope at all.
///
/// In particular `ProviderTerminalObservation::terminal_ref` is NOT an
/// invocation scope and is never read as one: the `OpenCode` producer emits the
/// constant `"opencode:step-finish-stop"` for every step-finish event, and the
/// Codex producer emits the bound turn, which spans many invocations. Treating
/// either as an invocation identity would compare one shared constant against
/// every correlation, which is the same self-agreement defect as comparing a
/// record's digest to itself — only with a false positive instead of a vacuous
/// pass.
///
/// `ToolOutcomeClass::Unknown` is refused as well: the host classified the
/// outcome as unknown, and this adapter never infers success from an
/// unclassified outcome (I7.23: a missing or unclassified observation is
/// `UNKNOWN`, never a self-reported pass).
fn invocation_terminal_fact(
    event: &HostEventEnvelope,
) -> Result<InvocationTerminalFact<'_>, HostObservationReject> {
    let normalized = event
        .normalized()
        .map_err(|error| HostObservationReject::InvalidEnvelope(error.to_string()))?;
    match &normalized.payload {
        NormalizedHostEventPayload::ToolOutcome(observation) => {
            let state = match observation.outcome {
                ToolOutcomeClass::Succeeded => HostTerminalState::InvocationCompleted,
                ToolOutcomeClass::Failed | ToolOutcomeClass::Cancelled => {
                    HostTerminalState::InvocationError
                }
                ToolOutcomeClass::Unknown => {
                    return Err(HostObservationReject::UnclassifiedInvocationOutcome);
                }
            };
            Ok(InvocationTerminalFact {
                state,
                invocation_ref: observation.invocation_ref.as_str(),
                tool_name: observation.tool_name.as_str(),
            })
        }
        NormalizedHostEventPayload::ToolInvocation(_) => Err(
            HostObservationReject::NonTerminalKind("tool_invocation".to_owned()),
        ),
        _ => Err(HostObservationReject::InvocationScopeUnattributable),
    }
}

/// Normalizes one owner-nominated host event into a terminal observation.
///
/// Verifies envelope validity, reads the terminal state and invocation scope out
/// of the event's own closed observation, matches that scope against the exact
/// request identity the correlation itself recorded, checks the exact route
/// digest, and joins the event's *own* observed generation against BOTH the
/// generation the correlation recorded and the owner's live current session.
///
/// The observed side is read from the closed, versioned normalized observation
/// the envelope carries (never from caller input and never from the wire's
/// generic JSON). The expected side is the correlation's own recorded
/// [`RecordedInvocation`] — read back out of the correlation's immutable
/// identity, never restated by the joining caller — plus the owner's own live
/// attach binding and its own observed route fingerprint ([`HostOwnerBinding`]).
/// The evidence records the owner-sourced generation verbatim, so a correlation
/// never carries a generation the join caller asserted, and it records the
/// recorded correlation digest rather than a key the caller restated.
///
/// Non-terminal outcomes, unclassified outcomes, events that name no invocation,
/// foreign invocations or tools, foreign routes, unattributable lineage, and
/// stale or mismatched generations are rejected: missing or mismatched telemetry
/// is never relabeled as a host fault, and the correlation stays pending.
pub fn normalize_terminal_observation(
    event: &HostEventEnvelope,
    keys: &HostEventJoinKeys,
    owner: &HostOwnerBinding,
    recorded: &RecordedInvocation,
) -> Result<HostTerminalObservation, HostObservationReject> {
    event
        .validate()
        .map_err(|error| HostObservationReject::InvalidEnvelope(error.to_string()))?;
    // A terminal host fact must name the exact invocation it closes, and the
    // terminal state itself comes from the host's own classified outcome — never
    // from the envelope's `kind`, which is the wire's coarse host choice and is
    // not validated against the closed payload.
    let fact = invocation_terminal_fact(event)?;
    // The invocation scope the host's integration minted must be the exact MCP
    // request identity the serving boundary recorded. Route and session are not
    // a substitute — every correlation on the route shares both, so accepting on
    // them is exactly the false attribution this gate exists to prevent. An
    // event naming another invocation, another tool, or nothing at all closes no
    // correlation, and the correlation stays pending.
    if fact.invocation_ref != recorded.request_id {
        return Err(HostObservationReject::InvocationMismatch {
            expected: recorded.request_id.clone(),
            observed: fact.invocation_ref.to_owned(),
        });
    }
    if let Some(tool_name) = recorded.tool_name.as_deref()
        && tool_name != fact.tool_name
    {
        return Err(HostObservationReject::ToolMismatch {
            expected: tool_name.to_owned(),
            observed: fact.tool_name.to_owned(),
        });
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
    // Two exact generation joins, both against a recorded value rather than
    // against anything the caller supplied: the event must be from the same
    // generation the invocation was emitted under, AND that generation must
    // still be the owner's live one. The first stops a rotated host from
    // relabelling an old invocation as current; the second stops a retained
    // correlation from being closed by a later session's events.
    if let Some(recorded_session) = recorded.session_id.as_deref()
        && recorded_session != observed_session.as_str()
    {
        return Err(HostObservationReject::RecordedGenerationMismatch {
            observed: observed_session.as_str().to_owned(),
            recorded: recorded_session.to_owned(),
        });
    }
    if observed_session.as_str() != owner.session_id {
        return Err(HostObservationReject::StaleGeneration {
            observed: observed_session.as_str().to_owned(),
            current: owner.session_id.clone(),
        });
    }
    let event_json = serde_json::to_string(event)
        .map_err(|error| HostObservationReject::InvalidEnvelope(error.to_string()))?;
    Ok(HostTerminalObservation::Observed {
        state: fact.state,
        evidence: Box::new(HostObservationEvidence {
            integration_id: keys.integration_id.clone(),
            installation_id: owner.installation_id.clone(),
            session_generation: owner.session_id.clone(),
            process_generation: owner.activation_generation.clone(),
            correlation_digest: recorded.correlation_digest.clone(),
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
