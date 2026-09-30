//! Agent Bridge join for MCP invocation correlation.
//!
//! Issue #2899, item 5: local emission and host observations are submitted
//! through the existing admitted event owner — [`AgentBridgeCore`] — which
//! owns durable event identity, replay, and coverage gaps. The stdio facade
//! maintains no process-local correlation table and declares no terminal host
//! fact from tracing alone.
//!
//! The bridge instance stays owned by the bridge-owning process (which alone
//! can attach, journal, and forward); every function here takes it by
//! parameter. The facade invokes none of these functions — it owns no bridge
//! and must not mint a second journal — so this module is the typed seam the
//! owning process calls with its live bridge:
//!
//! - [`submit_derived_fault`] files one derived transport edge;
//! - [`read_host_coverage`] projects the owner's coverage denominator and the
//!   owner's own stale-UI/CLI display note;
//! - [`reconcile_terminal_event`] joins a nominated host event onto the live
//!   journal by exact identity, position, content, and generation, checks it
//!   against the evidence this correlation already accepted, and only then
//!   assesses it against an emission observation;
//! - [`reconcile_deadline_sweep`] assesses the stuck/pending boundary from the
//!   live journal without a terminal event.
//!
//! No expected set is ever taken from the joining caller. Event identity,
//! position, and content are compared against the retained owner journal;
//! the live generation and the expected route fingerprint are read from the
//! owner's own attach binding and the owner's own observed route; and a later
//! event is compared against the evidence read back out of the correlation's
//! own retained revisions. Comparing two values the caller supplied, or
//! recomputing a fresh digest over what the join already holds, could only
//! prove that the caller agrees with itself.
//!
//! Desktop-visible terminal state is read the same way. The owner's stale
//! UI/CLI display note is the owner's own retained record — it is set only by
//! [`AgentBridgeCore::note_stale_ui_disposition`], survives in
//! [`crate::TerminalReductionInputs`] and is projected here as
//! [`BridgeHostCoverage::stale_ui_noted`] — so the confirmation
//! [`assess_correlation`] receives is the owner's record and not a joining
//! caller's claim. It is absent from this seam's request types on purpose: a
//! bare `bool` here would let any caller assert "the host says the UI is
//! current" (or its opposite) with no observation behind it, and would decide
//! whether a healthy completion offers a refresh. That is a proof claim, and
//! [`AgentBridgeCore::note_stale_ui_disposition`] is the only thing that may
//! make it.
//!
//! The correlation identity is deliberately NOT an input to this join. A
//! correlation's recorded digest names the correlation; it says nothing about
//! which host event belongs to it, so requiring the caller to echo that digest
//! back would compare a record against itself and pass for every candidate. The
//! only thing that can attribute an event to one exact invocation is the
//! event's own owner-validated observation, read against the request identity
//! the correlation itself recorded ([`RecordedInvocation`]), and that is what
//! [`normalize_terminal_observation`] requires. An event that carries no
//! invocation scope, or that names another invocation, is refused, so no event
//! can close a correlation merely because that correlation was the one still
//! pending.
//!
//! Contiguity is a property of the *owner journal*, not of any one
//! invocation, so a proven interval is never coverage until it is bounded to
//! the correlation being assessed. [`reconcile_terminal_event`] requires the
//! proven interval to reach the candidate's own journaled sequence, and
//! [`reconcile_deadline_sweep`] requires it to continue one sequence past the
//! owner's highest, both read from the owner rather than from the request. A
//! long-contiguous run of *other* invocations' events therefore leaves the
//! outcome unknown instead of reading as an owner-proven clean interval
//! (issue #2899 item 7; I7.23 "missing host coverage is `TAINTED/UNKNOWN`,
//! never a self-reported PASS").
//!
//! Everything this seam retains is bounded and owned elsewhere. The expected
//! sets are the owner's journal, capped by the owner's
//! `TERMINAL_JOURNAL_CAPACITY` with an explicit eviction policy (the oldest
//! entry rotates out and the owner raises its incomplete-coverage flag, which
//! makes [`read_host_coverage`] report indeterminacy rather than a clean
//! interval), and the per-invocation `AssessmentLog` in `crate::mcp_correlation`,
//! capped by `MAX_ASSESSMENT_REVISIONS` and dropped with its invocation. There
//! is no facade-side table: nothing in this module is a second store, and no
//! terminal host fact is produced without an owner journal entry behind it.

use crate::mcp_correlation::{
    Assessment, AssessmentInputs, AssessmentLog, AssessmentRevision, CanonicalDisposition,
    CoverageIndeterminacy, CoverageProof, EliotEmissionObservation, HostTerminalObservation,
    ObservationWindow, OwnerValidatedOperationBinding, PartialObservation, assess_correlation,
    sha256_hex,
};
use crate::mcp_host_observation::{
    HostEventJoinKeys, HostObservationReject, HostOwnerBinding, RecordedInvocation,
    check_event_replay, normalize_terminal_observation,
};
use crate::{
    AgentBridgeCore, HostEventEnvelope, RouteFingerprint, TransportEdge, TransportEdgeKind,
};

/// Whether a derived fault filed a bridge transport edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultEdgeSubmission {
    /// A transport edge was filed for the derived fault.
    Submitted,
    /// The assessment state files no edge (pending, completed, local-only).
    NoEdgeForState,
}

/// Files one owner-recorded transport edge for a derived fault revision.
///
/// Stuck-after-deadline files a timeout edge; proven transport loss files a
/// disconnect edge. Pending, completed, consistent-error, misclassified, and
/// local-emission-failed states file nothing: misclassification rides the
/// journaled host event itself, and local failures are not bridge transport
/// facts. The owner supplies the edge sequence from its live journal; zero
/// fails closed in the owner constructor.
///
/// The return type is the plain outcome, not `Result<_, BridgeError>`. Filing
/// a derived edge is a best-effort annotation of an already-derived
/// assessment, and every production caller asks only whether the edge was
/// filed: no caller inspects, propagates or logs the owner's error, so
/// returning it would be returning a large value every caller immediately
/// discards. A rejected edge therefore reports
/// [`FaultEdgeSubmission::NoEdgeForState`], which is exactly the honest
/// meaning: the owner holds no edge for this revision. It is never reported as
/// a host fact and never advances a fault conclusion.
pub fn submit_derived_fault(
    bridge: &mut AgentBridgeCore,
    revision: &AssessmentRevision,
    sequence: u64,
) -> FaultEdgeSubmission {
    use crate::mcp_correlation::CorrelationAssessmentState;
    let assessment = &revision.assessment;
    let kind = match assessment.state {
        CorrelationAssessmentState::HostRespondingStuckAfterDeadline => TransportEdgeKind::Timeout,
        CorrelationAssessmentState::TransportLostAfterFlush => TransportEdgeKind::Disconnect,
        CorrelationAssessmentState::EmissionSucceededAwaitingHostObservation
        | CorrelationAssessmentState::HostObservationUnavailableOrGapped
        | CorrelationAssessmentState::HostCompleted
        | CorrelationAssessmentState::HostReportedInvocationError
        | CorrelationAssessmentState::ResponseMisclassifiedByHost
        | CorrelationAssessmentState::TransportOutcomeUnknown
        | CorrelationAssessmentState::EliotEmissionFailed => {
            return FaultEdgeSubmission::NoEdgeForState;
        }
    };
    let event_ref = assessment.evidence.host_event.as_ref().map_or_else(
        || format!("correlation:{}", revision.identity_digest),
        |evidence| evidence.event_id.clone(),
    );
    let Ok(edge) = TransportEdge::record(
        kind,
        event_ref,
        sequence,
        format!(
            "correlation {} revision {} state {}",
            revision.identity_digest,
            revision.revision,
            assessment.state.as_str()
        ),
    ) else {
        return FaultEdgeSubmission::NoEdgeForState;
    };
    if bridge.record_transport_edge(edge).is_err() {
        return FaultEdgeSubmission::NoEdgeForState;
    }
    FaultEdgeSubmission::Submitted
}

/// Host-event coverage projected from the live owner journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeHostCoverage {
    /// Owner-proven coverage over the host-event interval.
    pub coverage: CoverageProof,
    /// Journaled host events observed.
    pub history_len: usize,
    /// Whether the owner noted a stale UI disposition.
    ///
    /// Read from the owner's own retained note, not from the caller. This is
    /// the project's Desktop-visible terminal state: it is `false` when the
    /// owner has noted nothing, which is absence and is not a statement that
    /// the surface is current. [`reconcile_terminal_event`] and
    /// [`reconcile_deadline_sweep`] both take the confirmation they assess
    /// from here, so no other seam in this module has to carry it.
    pub stale_ui_noted: bool,
}

/// Projects the host-event coverage denominator from the live owner journal.
///
/// Contiguous journals prove a complete interval; a sequence break proves a
/// cursor gap; rotation proves indeterminacy; an unattached owner proves
/// nothing. Coverage comes only from this owner projection, never from
/// facade-local guessing.
///
/// The result is a property of the *journal*, not of any one invocation, so
/// it is only coverage once bounded to the correlation under assessment: see
/// [`ObservationWindow::covers_this_correlation`]. A journal that is
/// contiguous but stops short of that correlation's own sequence yields
/// [`CoverageProof::Indeterminate`] downstream, not a clean interval.
///
/// The journal is the denominator and it is bounded by the owner, not by this
/// module: the owner caps it at its `TERMINAL_JOURNAL_CAPACITY`, evicts the
/// oldest entry when full, and raises its own incomplete-coverage flag on that
/// eviction, which surfaces here as
/// [`CoverageProof::Indeterminate`] rather than as a silently shorter
/// interval. Rejection is therefore explicit: a rotated or absent journal
/// yields `Indeterminate`, and a gap yields
/// [`CoverageProof::CursorGap`], so no assessment downstream can read a bounded
/// but incomplete interval as complete coverage.
///
/// The projection also carries the owner's own stale UI/CLI display note as
/// [`BridgeHostCoverage::stale_ui_noted`], so the Desktop-visible terminal
/// state an assessment carries is read from the same owner record in the same
/// call rather than supplied by the joining caller.
pub fn read_host_coverage(bridge: &AgentBridgeCore) -> BridgeHostCoverage {
    let Some(inputs) = bridge.terminal_reduction_inputs() else {
        return BridgeHostCoverage {
            coverage: CoverageProof::Indeterminate {
                cause: CoverageIndeterminacy::OwnerUnattached,
            },
            history_len: 0,
            stale_ui_noted: false,
        };
    };
    let history = inputs.history();
    let stale_ui_noted = inputs.stale_ui_disposition().is_some();
    if history.is_empty() {
        return BridgeHostCoverage {
            coverage: CoverageProof::NoEventYet,
            history_len: 0,
            stale_ui_noted,
        };
    }
    if inputs.coverage().incomplete_coverage() {
        return BridgeHostCoverage {
            coverage: CoverageProof::Indeterminate {
                cause: CoverageIndeterminacy::JournalRotated,
            },
            history_len: history.len(),
            stale_ui_noted,
        };
    }
    let mut last_contiguous = history[0].sequence;
    for pair in history.windows(2) {
        if pair[1].sequence == pair[0].sequence + 1 {
            last_contiguous = pair[1].sequence;
        } else {
            return BridgeHostCoverage {
                coverage: CoverageProof::CursorGap {
                    last_contiguous_seq: last_contiguous,
                    highest_observed_seq: history[history.len() - 1].sequence,
                },
                history_len: history.len(),
                stale_ui_noted,
            };
        }
    }
    BridgeHostCoverage {
        coverage: CoverageProof::CompleteInterval {
            from_seq: history[0].sequence,
            to_seq: history[history.len() - 1].sequence,
        },
        history_len: history.len(),
        stale_ui_noted,
    }
}

/// Why terminal-event reconciliation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileError {
    /// The event owner is unattached; no journal exists to verify against.
    OwnerUnattached,
    /// The event owner has observed no route fingerprint, so the candidate's
    /// route cannot be checked against anything the owner recorded and it
    /// closes nothing current.
    OwnerRouteUnproven,
    /// The nominated event is absent from the live owner journal.
    NominatedEventNotJournaled {
        /// Nominated event identity.
        event_id: String,
    },
    /// The nominated event identity is not bound to exactly the position the
    /// owner declared for it, so a late or reordered observation closes
    /// nothing.
    OutOfDeclaredOrder {
        /// Conflicting event identity.
        event_id: String,
        /// Position the candidate claimed in the owner's observation order.
        sequence: u64,
    },
    /// The journal holds different content under the nominated event identity.
    JournalContentConflict {
        /// Conflicting event identity.
        event_id: String,
    },
    /// The same event identity was already accepted for this correlation with
    /// different content, generation, route, or cursor.
    PriorEvidenceConflict {
        /// Conflicting event identity.
        event_id: String,
    },
    /// The candidate failed host-observation normalization.
    HostRejected(HostObservationReject),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OwnerUnattached => formatter
                .write_str("event owner is unattached; cannot verify the nominated host event"),
            Self::OwnerRouteUnproven => formatter.write_str(
                "event owner recorded no route fingerprint; the nominated host event closes nothing",
            ),
            Self::NominatedEventNotJournaled { event_id } => write!(
                formatter,
                "nominated host event {event_id} is absent from the owner journal"
            ),
            Self::OutOfDeclaredOrder { event_id, sequence } => write!(
                formatter,
                "host event {event_id} is not at its declared journal position {sequence}"
            ),
            Self::JournalContentConflict { event_id } => write!(
                formatter,
                "owner journal holds different content for host event {event_id}"
            ),
            Self::PriorEvidenceConflict { event_id } => write!(
                formatter,
                "host event {event_id} was already accepted for this correlation with \
                 different content"
            ),
            Self::HostRejected(reason) => {
                write!(formatter, "host event rejected for correlation: {reason}")
            }
        }
    }
}

impl std::error::Error for ReconcileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HostRejected(reason) => Some(reason),
            Self::OwnerUnattached
            | Self::OwnerRouteUnproven
            | Self::NominatedEventNotJournaled { .. }
            | Self::OutOfDeclaredOrder { .. }
            | Self::JournalContentConflict { .. }
            | Self::PriorEvidenceConflict { .. } => None,
        }
    }
}

/// Owner request to reconcile one nominated terminal host event.
///
/// Desktop-visible terminal state is deliberately NOT a field. It is read from
/// the owner's own stale UI/CLI display note inside
/// [`reconcile_terminal_event`], because a bare `bool` carried here would be
/// the joining caller's assertion rather than an observation, and it is what
/// decides whether a healthy completion offers a refresh.
pub struct TerminalReconcileRequest<'a> {
    /// Immutable ELIOT-side emission observation being reconciled.
    pub emission: &'a EliotEmissionObservation,
    /// Owner-nominated candidate host event from the live journal.
    pub candidate: &'a HostEventEnvelope,
    /// Exact join keys the owner attests for the candidate.
    pub keys: &'a HostEventJoinKeys,
    /// This correlation's own append-only assessment chain.
    ///
    /// This is the independent expected set for a later event: the join reads
    /// the evidence already accepted back out of the correlation's own
    /// retained revisions and compares the new candidate against that record.
    /// It is not a caller-supplied expected set — accepting a caller-presented
    /// `None` would let one correlation close once per event.
    pub assessments: &'a AssessmentLog,
    /// Owner-validated operation binding, when a tool owner minted one.
    pub operation_binding: Option<&'a OwnerValidatedOperationBinding>,
    /// Canonical disposition from canonical evidence only.
    pub canonical: &'a CanonicalDisposition,
    /// Owner clock at assessment time, when the owner supplied one.
    pub now_unix_ms: Option<u64>,
}

/// Reconciles one nominated terminal host event against an emission.
///
/// The candidate is joined on exact event identity first, then exact content,
/// then exact generation, then against the evidence this correlation already
/// accepted:
///
/// 0. **exact identity** — the event identity must be present in the live
///    owner journal, and that identity must be bound to exactly the sequence
///    and cursor the candidate claims. An event that is absent, or that sits at
///    a different position than it claims, closes nothing;
/// 1. **exact content** — every journaled entry under that identity must equal
///    the candidate field for field. One differing entry is a same-identity
///    content conflict and is refused, never overwritten; byte-equal repeats
///    are an exact replay and stay idempotent;
/// 2. **exact generation** — the candidate's own owner-validated lineage must
///    name the session in the owner's own live attach binding, and its route
///    fingerprint must be the one the owner itself observed, so a restart or
///    session rotation cannot relabel an old observation as current;
/// 3. **attribution** — the candidate's own owner-validated observation must
///    name one exact invocation, and that invocation must be the exact request
///    identity this correlation itself recorded. This is the only step that can
///    establish that the event is about *this* correlation: the recorded digest
///    identifies the correlation but proves nothing about the event, and route,
///    session, and generation are shared by every correlation on the route. A
///    turn- or step-scoped terminal payload names no invocation and is refused
///    here, and so the correlation stays pending;
/// 4. **prior accepted evidence** — the same event identity may not reappear
///    for this correlation with any changed content, compared against the
///    evidence read back out of this correlation's own retained revisions.
///
/// Only then is the event assessed, with the owner's live coverage
/// denominator bounded to the candidate's own journaled sequence. Stale,
/// foreign, unattributable, duplicated, reordered, and out-of-order host events
/// each close nothing current.
///
/// The Desktop-visible terminal state the assessment carries is read from the
/// owner's own stale UI/CLI display note at that point, not from
/// [`TerminalReconcileRequest`]. No refusal above is affected by it: every
/// check that can return a [`ReconcileError`] has already run and returned by
/// the time the note is read, and the note reaches exactly one decision inside
/// [`assess_correlation`] — whether a `HostCompleted` outcome also offers
/// [`RecoveryAction`](crate::mcp_correlation::RecoveryAction)::RefreshDesktopView
/// — so it can add a recovery directive and can never withdraw one.
pub fn reconcile_terminal_event(
    bridge: &AgentBridgeCore,
    request: &TerminalReconcileRequest<'_>,
) -> Result<Assessment, ReconcileError> {
    let Some(inputs) = bridge.terminal_reduction_inputs() else {
        return Err(ReconcileError::OwnerUnattached);
    };
    let recorded_digest = request.emission.identity.identity_digest.as_str();
    let journaled = journal_binding(inputs.history(), request.candidate)?;
    let owner = owner_binding(bridge, inputs.fingerprint())?;
    // The recorded invocation is read back out of the correlation's own
    // immutable identity here, so the joining caller cannot nominate either the
    // correlation or the invocation it claims the event belongs to. The join
    // holds exactly this emission observation, so this is a value against a
    // value: the host's own minted invocation scope against the MCP request
    // identity the serving boundary recorded.
    let recorded = RecordedInvocation {
        correlation_digest: recorded_digest.to_owned(),
        request_id: request.emission.identity.mcp_request_id.clone(),
        tool_name: request.emission.identity.tool_name.clone(),
        session_id: request.emission.identity.session_id.clone(),
    };
    let host = normalize_terminal_observation(journaled, request.keys, &owner, &recorded)
        .map_err(ReconcileError::HostRejected)?;
    // An exact replay is idempotent: identical evidence re-derives the
    // identical assessment, so the correlation still closes exactly once, and a
    // different event identity is a new observation of the same correlation.
    // Neither rewrites a prior revision by itself. Only the same identity with
    // changed content — a different generation, route, cursor, or digest — is
    // refused. The expected set is this correlation's own retained record, not
    // anything the joining caller presents.
    if let (Some(prior), HostTerminalObservation::Observed { evidence, .. }) =
        (request.assessments.latest_host_evidence(), &host)
        && check_event_replay(prior, evidence.as_ref()).is_err()
    {
        return Err(ReconcileError::PriorEvidenceConflict {
            event_id: journaled.event_id.as_str().to_owned(),
        });
    }
    let coverage = read_host_coverage(bridge);
    // Desktop-visible terminal state is read out of the owner's own retained
    // stale UI/CLI display note, from the same owner projection the coverage
    // denominator comes from, and before `coverage.coverage` is moved into the
    // window below. The owner sets that note only through
    // `AgentBridgeCore::note_stale_ui_disposition`, so a `true` here is an
    // observation the owner recorded; an absent note is absence, never a claim
    // that the Desktop view is current.
    let ui_confirmed_stale = coverage.stale_ui_noted;
    let window = ObservationWindow {
        deadline_unix_ms: request.keys.deadline_unix_ms,
        now_unix_ms: request.now_unix_ms,
        coverage: coverage.coverage,
        required_seq: Some(journaled.sequence),
    };
    let transport_edge = inputs
        .edges()
        .iter()
        .find(|edge| edge.event_ref() == journaled.event_id.as_str())
        .map(TransportEdge::kind);
    let assessment_inputs = AssessmentInputs {
        emission: request.emission,
        host: &host,
        window: &window,
        transport_edge,
        operation_binding: request.operation_binding,
        canonical: request.canonical,
        ui_confirmed_stale,
    };
    Ok(assess_correlation(&assessment_inputs))
}

/// Reads the live generation this join compares against, from the owner only.
///
/// The expected side of the generation join is the owner's own live attach
/// binding and the route fingerprint the owner itself observed, so the
/// comparison is a value against a value: the event's own owner-validated
/// lineage against the owner's own record. A route the owner has not observed
/// proves nothing, so the candidate closes nothing rather than being compared
/// against a digest the join computed over its own inputs.
fn owner_binding(
    bridge: &AgentBridgeCore,
    observed_route: Option<&RouteFingerprint>,
) -> Result<HostOwnerBinding, ReconcileError> {
    let binding = bridge
        .attach_view()
        .map(|view| view.binding().clone())
        .ok_or(ReconcileError::OwnerUnattached)?;
    let route = observed_route.ok_or(ReconcileError::OwnerRouteUnproven)?;
    let route_json = route.canonical_json().map_err(|error| {
        ReconcileError::HostRejected(HostObservationReject::InvalidEnvelope(error.to_string()))
    })?;
    Ok(HostOwnerBinding {
        installation_id: binding.principal_id().as_str().to_owned(),
        session_id: binding.session_id().as_str().to_owned(),
        activation_generation: binding.activation_generation().to_string(),
        route_digest: sha256_hex(route_json.as_bytes()),
    })
}

/// Joins one nominated candidate onto the owner's declared observation order.
///
/// Exact identity, never a prefix match. The event identity must be present in
/// the retained journal, and that identity must be bound to exactly the
/// sequence and cursor the candidate claims, and the journal position holding
/// that sequence must hold that identity: an absent, foreign, reordered, or
/// late observation therefore closes nothing. Every entry filed under the same
/// identity must also be byte-equal to the candidate, so one differing entry is
/// a same-identity content conflict while byte-equal repeats stay an idempotent
/// replay. The owner journal is the only expected set consulted; the facade
/// keeps no table of its own.
fn journal_binding<'a>(
    history: &'a [HostEventEnvelope],
    candidate: &HostEventEnvelope,
) -> Result<&'a HostEventEnvelope, ReconcileError> {
    let event_id = candidate.event_id.as_str().to_owned();
    let bound = history
        .iter()
        .filter(|event| event.event_id.as_str() == event_id)
        .collect::<Vec<_>>();
    let Some(first) = bound.first() else {
        return Err(ReconcileError::NominatedEventNotJournaled { event_id });
    };
    if bound
        .iter()
        .any(|event| event.sequence != candidate.sequence || event.cursor != candidate.cursor)
    {
        return Err(ReconcileError::OutOfDeclaredOrder {
            event_id,
            sequence: candidate.sequence,
        });
    }
    if bound.iter().any(|event| *event != candidate) {
        return Err(ReconcileError::JournalContentConflict {
            event_id: event_id.clone(),
        });
    }
    let at_declared = history
        .iter()
        .find(|event| event.sequence == candidate.sequence);
    if at_declared.is_none_or(|event| event.event_id.as_str() != event_id) {
        return Err(ReconcileError::OutOfDeclaredOrder {
            event_id,
            sequence: candidate.sequence,
        });
    }
    Ok(*first)
}

/// Owner request to assess the stuck/pending boundary without a terminal event.
pub struct DeadlineSweepRequest<'a> {
    /// Immutable ELIOT-side emission observation being assessed.
    pub emission: &'a EliotEmissionObservation,
    /// Applicable observation deadline admitted by the owner, when one exists.
    pub deadline_unix_ms: Option<u64>,
    /// Owner-validated operation binding, when a tool owner minted one.
    pub operation_binding: Option<&'a OwnerValidatedOperationBinding>,
    /// Canonical disposition from canonical evidence only.
    pub canonical: &'a CanonicalDisposition,
    /// Owner clock at assessment time, when the owner supplied one.
    pub now_unix_ms: Option<u64>,
}

/// Assesses the stuck/pending boundary from the live journal, no terminal.
///
/// With no terminal event, only an owner-proven complete interval past the
/// admitted deadline establishes stuck; every other denominator stays
/// pending or unknown. Never files edges and never invents host completion.
///
/// The sweep names no candidate event, so the sequence its coverage must reach
/// is derived from the owner's own journal rather than from the request: the
/// terminal event for a still-pending correlation would be the next one the
/// owner admits, so contiguity proves coverage only once the journal actually
/// continued past it. A journal that stopped short — including a long-contiguous
/// one covering only *earlier, unrelated* invocations — leaves the outcome
/// `UNKNOWN`, never stuck (issue #2899 item 7; I7.23).
pub fn reconcile_deadline_sweep(
    bridge: &AgentBridgeCore,
    request: &DeadlineSweepRequest<'_>,
) -> Assessment {
    let coverage = read_host_coverage(bridge);
    // The same owner-read note the terminal-event join uses, taken from the
    // same owner projection. Here it cannot change any outcome: with no
    // terminal event the host observation is `PartialUnknown`, so
    // `assess_correlation` cannot reach the `HostCompleted` arm that is the
    // only reader of the confirmation. It is read from the owner rather than
    // written as a literal so that no seam in this module states "the Desktop
    // view is current" without an owner record behind it.
    let ui_confirmed_stale = coverage.stale_ui_noted;
    let window = ObservationWindow {
        deadline_unix_ms: request.deadline_unix_ms,
        now_unix_ms: request.now_unix_ms,
        coverage: coverage.coverage,
        required_seq: pending_required_seq(bridge),
    };
    let host = HostTerminalObservation::PartialUnknown(PartialObservation::stdio_boundary());
    let assessment_inputs = AssessmentInputs {
        emission: request.emission,
        host: &host,
        window: &window,
        transport_edge: None,
        operation_binding: request.operation_binding,
        canonical: request.canonical,
        ui_confirmed_stale,
    };
    assess_correlation(&assessment_inputs)
}

/// Host-event sequence a still-pending correlation must reach before a
/// proven interval says anything about it.
///
/// Read from the owner's live journal, never from the requesting caller: a
/// caller-supplied floor could be set arbitrarily low and would then let a
/// short interval cover an unrelated invocation. With no journal at all the
/// owner has admitted no sequence binding, which is indeterminacy and leaves
/// the correlation pending.
fn pending_required_seq(bridge: &AgentBridgeCore) -> Option<u64> {
    let inputs = bridge.terminal_reduction_inputs()?;
    let highest = inputs.history().last()?.sequence;
    Some(highest.saturating_add(1))
}
