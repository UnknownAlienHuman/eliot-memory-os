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
//! - [`submit_host_event`] journals one host event through `forward_hook`;
//! - [`submit_derived_fault`] files one derived transport edge;
//! - [`read_host_coverage`] projects the owner's coverage denominator;
//! - [`reconcile_terminal_event`] joins a nominated host event onto the live
//!   journal by exact identity, position, content, and generation, checks it
//!   against the evidence this correlation already accepted, and only then
//!   assesses it against an emission observation;
//! - [`reconcile_deadline_sweep`] assesses the stuck/pending boundary from the
//!   live journal without a terminal event.
//!
//! No expected set is ever taken from the joining caller. Event identity,
//! position, and content are compared against the retained owner journal;
//! generation is compared against the owner's live attach binding; and a later
//! event is compared against the evidence the correlation itself already
//! accepted. Comparing two values the caller supplied could only prove that the
//! caller agrees with itself.
//!
//! Everything this seam retains is bounded and owned elsewhere. The expected
//! sets are the owner's journal, capped by the owner's
//! `TERMINAL_JOURNAL_CAPACITY` with an explicit eviction policy (the oldest
//! entry rotates out and the owner raises its incomplete-coverage flag, which
//! makes [`read_host_coverage`] report indeterminacy rather than a clean
//! interval), and the per-invocation `AssessmentLog` in `super::correlation`,
//! capped by `MAX_ASSESSMENT_REVISIONS` and dropped with its invocation. There
//! is no facade-side table: nothing in this module is a second store, and no
//! terminal host fact is produced without an owner journal entry behind it.

use eliot_agent_bridge_core::{
    AgentBridgeCore, HostEventEnvelope, TransportEdge, TransportEdgeKind,
};

use super::correlation::{
    Assessment, AssessmentInputs, AssessmentRevision, CanonicalDisposition, CoverageIndeterminacy,
    CoverageProof, EliotEmissionObservation, HostObservationEvidence, HostTerminalObservation,
    ObservationWindow, OwnerValidatedOperationBinding, PartialObservation, assess_correlation,
};
use super::host_observation::{
    HostEventJoinKeys, HostObservationReject, check_event_replay, normalize_terminal_observation,
};

/// Submits one host event through the existing admitted event route.
///
/// Journals the event in the owner's transport history and forwards it via
/// the admitted port. Fails closed when the bridge is unattached or the
/// event violates the owner contract.
pub(crate) fn submit_host_event(
    bridge: &mut AgentBridgeCore,
    event: &HostEventEnvelope,
) -> anyhow::Result<()> {
    Ok(bridge.forward_hook(event)?)
}

/// Whether a derived fault filed a bridge transport edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultEdgeSubmission {
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
pub(crate) fn submit_derived_fault(
    bridge: &mut AgentBridgeCore,
    revision: &AssessmentRevision,
    sequence: u64,
) -> anyhow::Result<FaultEdgeSubmission> {
    use super::correlation::CorrelationAssessmentState;
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
            return Ok(FaultEdgeSubmission::NoEdgeForState);
        }
    };
    let event_ref = assessment.evidence.host_event.as_ref().map_or_else(
        || format!("correlation:{}", revision.identity_digest),
        |evidence| evidence.event_id.clone(),
    );
    let edge = TransportEdge::record(
        kind,
        event_ref,
        sequence,
        format!(
            "correlation {} revision {} state {}",
            revision.identity_digest,
            revision.revision,
            assessment.state.as_str()
        ),
    )?;
    bridge.record_transport_edge(edge)?;
    Ok(FaultEdgeSubmission::Submitted)
}

/// Host-event coverage projected from the live owner journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BridgeHostCoverage {
    /// Owner-proven coverage over the host-event interval.
    pub(crate) coverage: CoverageProof,
    /// Journaled host events observed.
    pub(crate) history_len: usize,
    /// Whether the owner noted a stale UI disposition.
    pub(crate) stale_ui_noted: bool,
}

/// Projects the host-event coverage denominator from the live owner journal.
///
/// Contiguous journals prove a complete interval; a sequence break proves a
/// cursor gap; rotation proves indeterminacy; an unattached owner proves
/// nothing. Coverage comes only from this owner projection, never from
/// facade-local guessing.
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
pub(crate) fn read_host_coverage(bridge: &AgentBridgeCore) -> BridgeHostCoverage {
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
pub(crate) enum ReconcileError {
    /// The event owner is unattached; no journal exists to verify against.
    OwnerUnattached,
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
            | Self::NominatedEventNotJournaled { .. }
            | Self::OutOfDeclaredOrder { .. }
            | Self::JournalContentConflict { .. }
            | Self::PriorEvidenceConflict { .. } => None,
        }
    }
}

/// Owner request to reconcile one nominated terminal host event.
pub(crate) struct TerminalReconcileRequest<'a> {
    /// Immutable ELIOT-side emission observation being reconciled.
    pub(crate) emission: &'a EliotEmissionObservation,
    /// Owner-nominated candidate host event from the live journal.
    pub(crate) candidate: &'a HostEventEnvelope,
    /// Exact join keys the owner attests for the candidate.
    pub(crate) keys: &'a HostEventJoinKeys,
    /// Host observation already accepted for this same correlation, taken
    /// from the correlation's own retained revision chain.
    ///
    /// This is the independent expected set for a later event: the join
    /// compares a new candidate against the recorded evidence rather than
    /// against a fresh recomputation of the same inputs.
    pub(crate) prior_host_evidence: Option<&'a HostObservationEvidence>,
    /// Owner-validated operation binding, when a tool owner minted one.
    pub(crate) operation_binding: Option<&'a OwnerValidatedOperationBinding>,
    /// Canonical disposition from canonical evidence only.
    pub(crate) canonical: &'a CanonicalDisposition,
    /// Whether the owner confirms a stale UI for this invocation.
    pub(crate) ui_confirmed_stale: bool,
    /// Owner clock at assessment time, when the owner supplied one.
    pub(crate) now_unix_ms: Option<u64>,
}

/// Reconciles one nominated terminal host event against an emission.
///
/// The candidate is joined on exact identity first, then exact generation, then
/// exact content, then against the evidence this correlation already accepted:
///
/// 1. **exact identity** — the event identity must be present in the live
///    owner journal, and that identity must be bound to exactly the sequence
///    and cursor the candidate claims. An event that is absent, or that sits at
///    a different position than it claims, closes nothing;
/// 2. **exact content** — every journaled entry under that identity must equal
///    the candidate field for field. One differing entry is a same-identity
///    content conflict and is refused, never overwritten; byte-equal repeats
///    are an exact replay and stay idempotent;
/// 3. **exact generation** — the candidate's own owner-validated lineage must
///    name the owner's live current session, so a restart or session rotation
///    cannot relabel an old observation as current;
/// 4. **prior accepted evidence** — the same event identity may not reappear
///    for this correlation with any changed content.
///
/// Only then is the event assessed, with the owner's live coverage
/// denominator. Stale, foreign, duplicated, reordered, and out-of-order host
/// events each close nothing current.
pub(crate) fn reconcile_terminal_event(
    bridge: &AgentBridgeCore,
    request: &TerminalReconcileRequest<'_>,
) -> Result<Assessment, ReconcileError> {
    let Some(inputs) = bridge.terminal_reduction_inputs() else {
        return Err(ReconcileError::OwnerUnattached);
    };
    let journaled = journal_binding(inputs.history(), request.candidate)?;
    let current_session = bridge
        .attach_view()
        .map(|view| view.binding().session_id().as_str().to_owned())
        .ok_or(ReconcileError::OwnerUnattached)?;
    let host = normalize_terminal_observation(journaled, request.keys, &current_session)
        .map_err(ReconcileError::HostRejected)?;
    // An exact replay is idempotent: identical evidence re-derives the
    // identical assessment, so the correlation still closes exactly once, and a
    // different event identity is a new observation of the same correlation.
    // Neither rewrites a prior revision by itself. Only the same identity with
    // changed content — a different generation, route, cursor, or digest — is
    // refused.
    if let (Some(prior), HostTerminalObservation::Observed { evidence, .. }) =
        (request.prior_host_evidence, &host)
        && check_event_replay(prior, evidence.as_ref()).is_err()
    {
        return Err(ReconcileError::PriorEvidenceConflict {
            event_id: journaled.event_id.as_str().to_owned(),
        });
    }
    let coverage = read_host_coverage(bridge);
    let window = ObservationWindow {
        deadline_unix_ms: request.keys.deadline_unix_ms,
        now_unix_ms: request.now_unix_ms,
        coverage: coverage.coverage,
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
        ui_confirmed_stale: request.ui_confirmed_stale,
    };
    Ok(assess_correlation(&assessment_inputs))
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
pub(crate) struct DeadlineSweepRequest<'a> {
    /// Immutable ELIOT-side emission observation being assessed.
    pub(crate) emission: &'a EliotEmissionObservation,
    /// Applicable observation deadline admitted by the owner, when one exists.
    pub(crate) deadline_unix_ms: Option<u64>,
    /// Owner-validated operation binding, when a tool owner minted one.
    pub(crate) operation_binding: Option<&'a OwnerValidatedOperationBinding>,
    /// Canonical disposition from canonical evidence only.
    pub(crate) canonical: &'a CanonicalDisposition,
    /// Owner clock at assessment time, when the owner supplied one.
    pub(crate) now_unix_ms: Option<u64>,
}

/// Assesses the stuck/pending boundary from the live journal, no terminal.
///
/// With no terminal event, only an owner-proven complete interval past the
/// admitted deadline establishes stuck; every other denominator stays
/// pending or unknown. Never files edges and never invents host completion.
pub(crate) fn reconcile_deadline_sweep(
    bridge: &AgentBridgeCore,
    request: &DeadlineSweepRequest<'_>,
) -> Assessment {
    let coverage = read_host_coverage(bridge);
    let window = ObservationWindow {
        deadline_unix_ms: request.deadline_unix_ms,
        now_unix_ms: request.now_unix_ms,
        coverage: coverage.coverage,
    };
    let host = HostTerminalObservation::PartialUnknown(PartialObservation::stdio_boundary());
    let assessment_inputs = AssessmentInputs {
        emission: request.emission,
        host: &host,
        window: &window,
        transport_edge: None,
        operation_binding: request.operation_binding,
        canonical: request.canonical,
        ui_confirmed_stale: false,
    };
    assess_correlation(&assessment_inputs)
}
