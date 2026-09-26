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
//! - [`reconcile_terminal_event`] verifies a nominated host event verbatim in
//!   the live journal and assesses it against an emission observation;
//! - [`reconcile_deadline_sweep`] assesses the stuck/pending boundary from the
//!   live journal without a terminal event.

use eliot_agent_bridge_core::{
    AgentBridgeCore, HostEventEnvelope, TransportEdge, TransportEdgeKind,
};

use super::correlation::{
    Assessment, AssessmentInputs, AssessmentRevision, CanonicalDisposition, CoverageIndeterminacy,
    CoverageProof, EliotEmissionObservation, HostTerminalObservation, ObservationWindow,
    OwnerValidatedOperationBinding, PartialObservation, assess_correlation,
};
use super::host_observation::{
    HostEventJoinKeys, HostObservationReject, normalize_terminal_observation,
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
    /// The journal holds different content under the nominated event identity.
    JournalContentConflict {
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
            Self::JournalContentConflict { event_id } => write!(
                formatter,
                "owner journal holds different content for host event {event_id}"
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
            | Self::JournalContentConflict { .. } => None,
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
/// Verifies the candidate verbatim in the live owner journal (absent events
/// and changed same-identity content fail closed), normalizes it through the
/// host-event adapter, and assesses it against the emission observation with
/// the owner's live coverage denominator. Stale, foreign, duplicated, or
/// reordered host events cannot close a current correlation.
pub(crate) fn reconcile_terminal_event(
    bridge: &AgentBridgeCore,
    request: &TerminalReconcileRequest<'_>,
) -> Result<Assessment, ReconcileError> {
    let Some(inputs) = bridge.terminal_reduction_inputs() else {
        return Err(ReconcileError::OwnerUnattached);
    };
    let candidate_id = request.candidate.event_id.as_str();
    let Some(journaled) = inputs
        .history()
        .iter()
        .find(|event| event.event_id.as_str() == candidate_id)
    else {
        return Err(ReconcileError::NominatedEventNotJournaled {
            event_id: candidate_id.to_owned(),
        });
    };
    if journaled != request.candidate {
        return Err(ReconcileError::JournalContentConflict {
            event_id: candidate_id.to_owned(),
        });
    }
    let host = normalize_terminal_observation(request.candidate, request.keys)
        .map_err(ReconcileError::HostRejected)?;
    let coverage = read_host_coverage(bridge);
    let window = ObservationWindow {
        deadline_unix_ms: request.keys.deadline_unix_ms,
        now_unix_ms: request.now_unix_ms,
        coverage: coverage.coverage,
    };
    let transport_edge = inputs
        .edges()
        .iter()
        .find(|edge| edge.event_ref() == candidate_id)
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
