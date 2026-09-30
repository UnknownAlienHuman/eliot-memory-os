//! Live MCP stdio -> host-event -> Agent Bridge correlation for #2899.
//!
//! This is the production wiring the correlation vocabulary needs and did not
//! previously have. It lives in the bridge-owning process because the join
//! verifies against the owner's own live journal, attach binding and observed
//! route, and this process is the only holder of that owner.
//!
//! Two facts drive the whole shape:
//!
//! 1. **A correlation keyed only in process-local memory is not a
//!    correlation.** It dies with the process and a later host event cannot
//!    join it. So the ELIOT-side emission observation is submitted through the
//!    OWNER's existing admitted event route ([`BridgeRunner::forward_event`],
//!    the route every other bridge event already uses) and the owner retains
//!    it against the correlation identity digest. Nothing here is a second
//!    store and no second journal is minted.
//!
//! 2. **Tracing is an observation, not an authority.** Submitting an emission
//!    declares no host terminal fact. A host terminal state is established
//!    only when the candidate is present, byte-equal and correctly positioned
//!    in the owner's own journal, its own owner-validated lineage names the
//!    owner's live attach session, and its route is the route the owner itself
//!    observed. Otherwise the correlation stays pending or unknown, and a
//!    gapped or rotated journal is never reported as a host fault.
//!
//! Retention is bounded and the eviction is stated: at most
//! [`MAX_TRACKED_CORRELATIONS`] emission records are retained first-in
//! first-out. A rotated correlation is reported as
//! [`CorrelationTrackOutcome::RotationDropped`] and yields no assessment and
//! no fault — an evicted correlation is unknown, never degraded. Each
//! correlation's own assessment chain is separately capped inside the owner by
//! `MAX_ASSESSMENT_REVISIONS` and is dropped with its record.
//!
//! 3. **Reconciliation supersedes by appending; it never rewrites.** The
//!    emission receipt the owner already made durable is immutable and is never
//!    edited: a later host completion or an owner-proven fault appends a linked
//!    revision under the same correlation digest, and the CURRENT verdict is
//!    the latest revision, not the whole chain. A false degradation that a
//!    competent completion later contradicts therefore stops being current
//!    without a single historical byte changing. A repeated identical host
//!    event appends nothing at all, and a same-identity event whose content
//!    changed is refused as a typed conflict rather than overwriting anything.
//!
//! This module is a child of the crate root, so it can read
//! [`BridgeRunner`]'s private `core` field directly and join against the same
//! live owner the rest of the bridge uses. It adds no new owner, no parallel
//! journal, and no authority.

use eliot_agent_bridge_core::host_event::ToolOutcomeClass;
use eliot_agent_bridge_core::mcp_correlation::RecoveryDirective;
use eliot_agent_bridge_core::{
    AgentBridgeCore, Assessment, AssessmentLog, AssessmentSummary, BridgeError,
    CanonicalDisposition, CommitEvidence, CorrelationAssessmentState, CorrelationIdentity,
    CorrelationIdentityParts, CorrelationStage, CoverageProof, DeadlineSweepRequest,
    EliotEmissionObservation, EmissionCause, FaultEdgeSubmission, HandlerOutcome,
    HostEventEnvelope, HostEventJoinKeys, HostEventReplay, NormalizedHostEventPayload,
    OperationIdentity, OwnerValidatedOperationBinding, ReconcileError, ReplayConflict,
    StdioEmissionReceipt, TerminalReconcileRequest, check_event_replay, reconcile_deadline_sweep,
    reconcile_terminal_event, submit_derived_fault,
};
use eliot_contracts::{ResourceGeneration, StateFence};
use eliot_protocol::{DeliveryClass, EventEnvelope, EventPayload, ProtocolPayload};
use serde_json::Value;

use crate::BridgeRunner;

/// Exact `EventEnvelope::payload_type` of a submitted ELIOT emission
/// observation.
///
/// It names the closed, versioned record this route admits, so an ELIOT
/// emission is never confused with the host event it is later joined against.
/// The emission is NOT a host event and carries no host terminal state.
pub const MCP_EMISSION_PAYLOAD_TYPE: &str = "eliot.mcp-emission-observation.v1";

/// Producer identity of a submitted ELIOT emission observation.
///
/// It is the stdio boundary's own producer, distinct from the host adapter
/// that produces the retained host event. The two are facts about separate
/// processes and must not share an identity.
pub const MCP_EMISSION_PRODUCER_ID: &str = "eliot.mcp-stdio-boundary";

/// Reconciliation owner of a submitted ELIOT emission observation.
///
/// It names the existing bridge-event / ORS reconciliation owner, so the
/// emission rides the same durable route and the same ORS idempotency as every
/// other bridge event. This is the narrow current adapter the issue names, not
/// a second durable store.
pub const MCP_EMISSION_OWNER: &str = eliot_agent_opencode::HOST_EVENTS_DECISION_RECONCILER;

/// Maximum emission records this process retains for a later host-event join.
///
/// Bounded, with stated eviction: the oldest record rotates out and its
/// correlation becomes unknown rather than degraded.
pub const MAX_TRACKED_CORRELATIONS: usize = 256;

/// Outcome of submitting one emission observation for a later join.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorrelationTrackOutcome {
    /// The observation reached the owner and is now joinable.
    Tracked,
    /// The owner already held this exact correlation identity and content, so
    /// the record is unchanged and the correlation stays joinable. An exact
    /// replay is idempotent.
    Duplicate,
    /// The owner did not make this record durable, or the bounded set rotated
    /// an older record out. The affected correlation is unknown from here on
    /// and yields no assessment and no fault.
    RotationDropped,
}

/// How one admitted host event resolved against the live owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostEventReconciliation {
    /// The event joined a tracked correlation and resolved it to this state.
    Resolved {
        /// Correlation identity digest the event closed.
        correlation_digest: String,
        /// Derived assessment state.
        state: CorrelationAssessmentState,
        /// Whether the owner holds a transport edge for the event.
        edge_filed: bool,
        /// The correlation's CURRENT verdict after this reconciliation.
        verdict: CorrelationVerdict,
    },
    /// The event is not terminal, so it closes no correlation.
    NotTerminal,
    /// The event is terminal but no tracked correlation claimed it. This is
    /// the ordinary case for a host event that is not about an MCP invocation,
    /// and it is never a fault.
    NoTrackedCorrelation,
}

/// One correlation's CURRENT verdict, as reported to the operator.
///
/// "Current" is the appended revision that supersedes the previous one, never
/// the whole chain: a later healthy completion appended over an earlier
/// degradation becomes the record these fields describe, while the superseded
/// revision stays byte-identical in the log. Everything here is an identifier,
/// a closed reason code or a bounded count; no tool argument, response body or
/// host prose crosses this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationVerdict {
    /// Correlation identity digest this verdict belongs to.
    pub correlation_digest: String,
    /// State of the current revision.
    pub state: CorrelationAssessmentState,
    /// Monotonic revision number of the current revision.
    pub revision: u32,
    /// Revision this one supersedes, when it supersedes one.
    pub supersedes: Option<u32>,
    /// Owner-proven coverage the current verdict rested on. Whether that
    /// coverage is a complete interval or partial is reported explicitly; it is
    /// never inferred from optimism (I7.23).
    pub coverage: CoverageProof,
    /// Canonical operation disposition the current verdict was derived under.
    pub canonical_disposition: CanonicalDisposition,
    /// Bounded, typed recovery order for this verdict and disposition, when a
    /// lawful recovery exists. `None` means none is lawful.
    pub recovery: Option<String>,
}

impl CorrelationVerdict {
    /// Whether the coverage this verdict rested on is a complete observed
    /// interval rather than a gap or an absent denominator.
    pub const fn coverage_is_complete(&self) -> bool {
        self.coverage.is_complete_interval()
    }
}

/// Bounded result of one correlation deadline sweep.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorrelationSweepReport {
    /// Verdicts the sweep actually established, in retention order.
    pub verdicts: Vec<CorrelationVerdict>,
    /// Correlations the sweep refused to assess because the owner's live
    /// session is no longer the generation they were emitted under. A stale
    /// generation closes nothing, so these yield no verdict and no fault.
    pub stale_generation: u32,
    /// Correlations the sweep left alone because a competent host terminal had
    /// already closed them. A closed correlation is never re-assessed, so a
    /// degradation can never be appended over a healthy completion.
    pub already_closed: u32,
}

/// What the owner's join decided when one candidate was offered to every
/// retained correlation.
///
/// Named rather than spelled as a nested tuple so the two outcomes stay
/// readable at the call site: at most one correlation may accept, and a content
/// conflict is recorded separately so it can outrank that acceptance.
#[derive(Clone, Debug, Default)]
struct CandidateOffer {
    /// Index of the accepting correlation and the assessment it derived.
    accepted: Option<(usize, Assessment)>,
    /// Content conflict the join raised, when it raised one.
    conflict: Option<ReplayConflict>,
}

/// Why a terminal host event could not be reconciled at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileFailure {
    // Display is implemented below: the reconciliation path reports a failure
    // on the operator's stderr line rather than refusing an admission, and a
    // typed failure must stay typed on the way out — never stringified into the
    // variant itself.
    /// The event owner is unattached, so nothing can be verified against it.
    OwnerUnavailable,
    /// The event joined a correlation but the owner's own log refused the
    /// resulting revision, so no current assessment exists.
    RevisionRefused(String),
    /// More than one retained correlation accepted the same candidate event.
    ///
    /// Attribution is decided by the host event's own invocation scope, so this
    /// cannot happen while that scope is exact. It is refused rather than
    /// resolved by retention order: picking the first record would attribute a
    /// host terminal fact to whichever request happened to still be pending.
    AmbiguousAttribution(String),
    /// The same event identity was already accepted for a retained correlation
    /// with DIFFERENT content, or the owner journal holds conflicting content
    /// under one identity.
    ///
    /// This is a conflict, not a non-attribution, and it is deliberately not
    /// collapsed into one: the caller must be able to see that a mutation was
    /// refused rather than silently overwritten or silently ignored. Nothing is
    /// appended, no accepted revision is touched, and no edge is filed, so the
    /// prior observation stands exactly as recorded.
    ContentConflict(ReplayConflict),
}

impl std::fmt::Display for ReconcileFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OwnerUnavailable => {
                formatter.write_str("event owner unattached; nothing verified against it")
            }
            Self::RevisionRefused(detail) => {
                write!(formatter, "owner's log refused the revision: {detail}")
            }
            Self::AmbiguousAttribution(event_id) => write!(
                formatter,
                "host event {event_id} matched more than one correlation; it closes none"
            ),
            Self::ContentConflict(conflict) => write!(
                formatter,
                "host event content conflict; nothing appended and nothing closed: \
                 {conflict}"
            ),
        }
    }
}

impl std::error::Error for ReconcileFailure {}

/// One retained emission record plus its own bounded assessment chain.
#[derive(Clone, Debug)]
struct TrackedCorrelation {
    emission: EliotEmissionObservation,
    assessments: AssessmentLog,
    canonical: CanonicalDisposition,
    binding: Option<OwnerValidatedOperationBinding>,
    deadline_unix_ms: Option<u64>,
    /// Owner host-event sequence recorded when this emission was admitted.
    ///
    /// Read out of the owner's own journal at admission time, never recomputed
    /// later: it is the point the correlation's host-event interval has to be
    /// observed past before a contiguous run of events proves coverage FOR THIS
    /// correlation. Recomputing it at sweep time would make the gate
    /// unsatisfiable rather than strict, and skipping it would let a
    /// long-contiguous run of unrelated invocations read as proof.
    required_seq: Option<u64>,
}

/// Bounded first-in first-out retention of emission correlations.
#[derive(Clone, Debug, Default)]
pub(crate) struct CorrelationTracker {
    records: Vec<TrackedCorrelation>,
}

impl CorrelationTracker {
    /// Records one emission, reporting whether an older record rotated out.
    fn track(&mut self, record: TrackedCorrelation) -> CorrelationTrackOutcome {
        if let Some(existing) = self.records.iter_mut().find(|held| {
            held.emission.identity.identity_digest == record.emission.identity.identity_digest
        }) {
            // Same logical correlation. While it has no verdict yet there is
            // nothing to lose, so the freshest admitted deadline and coverage
            // floor replace the earlier ones. Once a verdict EXISTS the record
            // is left exactly as it is: a repeated emission of the same
            // identity must not discard the appended revision chain, or the
            // current verdict — including a healthy completion that superseded
            // an earlier degradation — would be silently dropped. Reconciliation
            // supersedes by appending, and nothing else may retract.
            if existing.assessments.latest().is_none() {
                *existing = record;
            }
            return CorrelationTrackOutcome::Duplicate;
        }
        let rotated = self.records.len() >= MAX_TRACKED_CORRELATIONS;
        if rotated {
            self.records.remove(0);
        }
        self.records.push(record);
        if rotated {
            CorrelationTrackOutcome::RotationDropped
        } else {
            CorrelationTrackOutcome::Tracked
        }
    }

    /// Live correlation records, oldest first.
    fn records(&self) -> &[TrackedCorrelation] {
        &self.records
    }

    /// Live correlation records for mutation, oldest first.
    fn records_mut(&mut self) -> &mut [TrackedCorrelation] {
        &mut self.records
    }

    /// Highest host sequence the owner currently retains, for edge filing.
    fn owner_sequence(&self, bridge: &AgentBridgeCore) -> u64 {
        let _ = self;
        bridge
            .terminal_reduction_inputs()
            .and_then(|inputs| inputs.history().last().map(|host| host.sequence))
            .unwrap_or(0)
    }

    /// Bounded pending/completed/degraded counts over CURRENT verdicts only.
    ///
    /// Each correlation contributes its latest revision, so a degradation that
    /// a later competent host completion superseded is not counted as current
    /// beside it. The superseded revision is never edited or removed; it simply
    /// stops being the record these counts describe.
    fn current_summary(&self) -> AssessmentSummary {
        AssessmentSummary::summarize_current(
            self.records
                .iter()
                .filter_map(|record| record.assessments.latest()),
        )
    }
}

/// Owner host-event sequence the owner has observed so far.
///
/// Read from the owner's own journal, never from the correlating caller. `None`
/// means the owner has admitted no host event yet, which is indeterminacy for
/// coverage purposes: the correlation records no sequence floor, and the sweep
/// therefore cannot claim a complete interval for it.
fn owner_observed_sequence(bridge: &AgentBridgeCore) -> Option<u64> {
    bridge
        .terminal_reduction_inputs()?
        .history()
        .last()
        .map(|event| event.sequence)
}

/// The session the owner's LIVE attach binding names.
///
/// The expected side of the generation join for the deadline sweep. The sweep
/// names no event, so its only generation evidence is the correlation's own
/// recorded session against this one; an event cannot be compared here because
/// there is none.
fn owner_live_session(bridge: &AgentBridgeCore) -> Option<String> {
    bridge
        .attach_view()
        .map(|view| view.binding().session_id().as_str().to_owned())
}

/// The owner-proven coverage one assessment rested on.
///
/// An assessment that recorded no coverage at all reports
/// [`CoverageProof::NoEventYet`] rather than a clean interval: absent coverage
/// is unknown, never a self-reported pass (I7.23).
fn coverage_of(assessment: &Assessment) -> CoverageProof {
    assessment
        .evidence
        .coverage
        .clone()
        .unwrap_or(CoverageProof::NoEventYet)
}

/// The bounded typed recovery order one assessment derived, as stable names.
///
/// `None` means no recovery is lawful for this state and disposition — a
/// healthy completion, a pending state and a local emission failure all recover
/// nothing. Only identifiers and closed action names cross this boundary.
fn recovery_of(assessment: &Assessment) -> Option<String> {
    assessment
        .recovery
        .as_ref()
        .map(RecoveryDirective::action_names)
}

/// Whether a resolved state attests healthy host completion, or a host error
/// that is consistent with the envelope ELIOT actually produced.
#[must_use]
pub fn is_healthy_completion(state: CorrelationAssessmentState) -> bool {
    matches!(
        state,
        CorrelationAssessmentState::HostCompleted
            | CorrelationAssessmentState::HostReportedInvocationError
    )
}

/// Whether one admitted host event is a competent per-invocation terminal
/// observation candidate.
///
/// The answer comes from the event's own closed, versioned normalized payload,
/// never from the wire's coarse `kind`: the host's terminal fact about one
/// invocation is its classified tool outcome, while a turn- or step-scoped
/// terminal kind (`Completed`, `Failed`, `Error`) names something coarser than a
/// single MCP request and can never close one. An unclassified outcome is not a
/// terminal fact either — the join derives the typed state from the same closed
/// payload, and refuses an unclassified one.
fn attests_invocation_terminal(event: &HostEventEnvelope) -> bool {
    event.normalized().is_ok_and(|normalized| {
        matches!(
            &normalized.payload,
            NormalizedHostEventPayload::ToolOutcome(observation)
                if !matches!(observation.outcome, ToolOutcomeClass::Unknown)
        )
    })
}

/// What the stdio boundary measured about one response emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioEmissionOutcome {
    /// Exact framed bytes placed on stdout.
    pub bytes: usize,
    /// Whether the stream flush succeeded.
    pub flushed: bool,
    /// Whether framing, serialization and the output bound all succeeded, so
    /// the only remaining question is delivery of bytes that were placed.
    pub emitted: bool,
}

impl StdioEmissionOutcome {
    /// Maps the boundary's own outcome onto the owner's typed receipt.
    ///
    /// A frame that never reached the pipe reports zero bytes even if the
    /// transport accepted a prefix, so `emitted_exactly_once` can never be
    /// true for a partial write.
    #[must_use]
    pub fn receipt(self) -> StdioEmissionReceipt {
        let cause = if !self.emitted {
            EmissionCause::WriteFailed
        } else if !self.flushed {
            EmissionCause::FlushFailed
        } else {
            EmissionCause::Emitted
        };
        StdioEmissionReceipt {
            bytes: if matches!(cause, EmissionCause::Emitted) {
                self.bytes
            } else {
                0
            },
            flushed: self.flushed && self.emitted,
            cause,
        }
    }
}

/// Owner-held facts about one stdio emission, read back from the owners that
/// issued them.
///
/// Every field is an owner read, never a claim from the wire and never an
/// inference from optimism:
///
/// * `failed_before_handler` comes from the front door's own dispatch
///   discipline — a frame that never reached a handler cannot have executed a
///   mutating stage, so it is a provable pre-stage failure;
/// * `owner_operation_receipt` is the exact Kernel-issued operation handle the
///   trusted port admitted for THIS correlation, read back from the front door's
///   per-correlation retention. It is a candidate canonical reference resolved
///   from the owner, never from any UI, so it can establish a possible commit
///   and nothing stronger;
/// * `deadline_unix_ms` is the exact absolute deadline the owner submitted for
///   this correlation, read back from the retained envelope it submitted. It is
///   the admitted settlement deadline, not a locally invented timeout.
///
/// `exact_readback_match` is deliberately NOT a field: no exact readback exists
/// at this boundary, so a committed disposition is never derivable here and the
/// canonical evidence always stays at "possible commit" or below.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StdioOwnerEmissionEvidence {
    /// Whether the request failed before any handler could run.
    pub failed_before_handler: bool,
    /// Exact Kernel-issued operation handle admitted for this correlation.
    pub owner_operation_receipt: Option<String>,
    /// Exact absolute deadline the owner submitted for this correlation.
    pub deadline_unix_ms: Option<u64>,
}

impl StdioOwnerEmissionEvidence {
    /// No owner evidence exists for this frame: nothing was admitted, so the
    /// canonical disposition stays whatever the facade can prove from the
    /// method alone.
    pub const fn none() -> Self {
        Self {
            failed_before_handler: false,
            owner_operation_receipt: None,
            deadline_unix_ms: None,
        }
    }
}

/// Integrates one MCP stdio emission and submits it to the owner.
///
/// This is the ELIOT-side producer on the live path. It observes only what
/// this process can measure for itself: the JSON-RPC request identity, the
/// method and tool, and the exact byte and flush receipt. It then freezes those
/// facts into the owner's immutable observation and submits them through the
/// owner's admitted route, so a later host event has something durable to join
/// against.
///
/// It declares no host terminal state. A successful emission yields a pending
/// record with an explicit `PartialUnknown` denominator, and only a later
/// admitted host event can resolve the correlation.
///
/// The canonical disposition is derived from the owner evidence the caller
/// read back plus the facade's own pre-stage fact, never from the caller's
/// hints: an admitted operation handle is a possible commit (reconciliation
/// still required), a pre-stage failure is a provable failed-before-stage, a
/// facade-owned protocol method is a read, and everything else is unknown. The
/// caller `write_id`/`idempotency_key` strings stay diagnostic and can never
/// authorize resubmission.
pub fn observe_mcp_emission(
    runner: &mut BridgeRunner,
    request: &Value,
    method: &str,
    tool_name: Option<&str>,
    outcome: StdioEmissionOutcome,
    evidence: &StdioOwnerEmissionEvidence,
) -> Result<CorrelationTrackOutcome, Box<BridgeError>> {
    let deadline_unix_ms = evidence.deadline_unix_ms;
    let params = request.get("params").unwrap_or(&Value::Null);
    let arguments = params.get("arguments").unwrap_or(&Value::Null);
    let operation = OperationIdentity::from_hints(
        arguments
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(str::to_owned),
        arguments
            .get("write_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
    );
    let tool = tool_name.map(str::to_owned).or_else(|| {
        params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let session = runner
        .core
        .attach_view()
        .map(|view| view.binding().session_id().as_str().to_owned());
    let identity = CorrelationIdentity::assemble(&CorrelationIdentityParts {
        mcp_request_id: request_id_text(request.get("id")),
        method: method.to_owned(),
        tool_name: tool,
        host_profile: Some(MCP_EMISSION_PRODUCER_ID.to_owned()),
        session_id: session,
        runtime_id: None,
        auth_generation: None,
        operation_binding: None,
    });
    let receipt = outcome.receipt();
    let stage = if receipt.flushed && matches!(receipt.cause, EmissionCause::Emitted) {
        CorrelationStage::Emitted
    } else {
        CorrelationStage::EmissionFailed
    };
    let emission = EliotEmissionObservation::observe(
        identity,
        stage,
        HandlerOutcome::CompletedOk,
        Some(outcome.bytes),
        Some(receipt),
    );
    let canonical = CanonicalDisposition::from_facade_evidence(
        method,
        evidence.failed_before_handler,
        &CommitEvidence {
            canonical_receipt_write_id: evidence.owner_operation_receipt.clone(),
            // No exact readback exists at this boundary, so this is never
            // `Some(true)`: a committed disposition stays underivable here.
            exact_readback_match: None,
        },
    );
    // The caller-supplied hints are diagnostic only and are never allowed to
    // authorize resubmission: no operation binding is passed, so the owner's
    // recovery derivation cannot offer same-operation replay from this path.
    tracing::info!(
        mcp_request_id = %emission.identity.mcp_request_id,
        identity_digest = %emission.identity.identity_digest,
        method = %emission.identity.method,
        tool_name = emission.identity.tool_name.as_deref().unwrap_or(""),
        operation_hint_present = !operation.is_empty(),
        idempotency_key_present = operation.idempotency_key.is_some(),
        owner_operation_bound = false,
        canonical_disposition = canonical.as_str(),
        admitted_deadline_present = deadline_unix_ms.is_some(),
        stage = stage.as_str(),
        response_bytes = outcome.bytes,
        emitted_exactly_once = emission.emitted_exactly_once(),
        "mcp emission observation submitted to the event owner"
    );
    runner.submit_emission_observation(&emission, canonical, None, deadline_unix_ms)
}

/// Milliseconds since the Unix epoch, or `None` when the host clock is
/// unavailable. Used only as the owner's own clock reading; a missing reading
/// never advances a deadline on its own.
#[must_use]
pub fn owner_now_unix_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
}

/// Stringifies a JSON-RPC id for the correlation identity.
fn request_id_text(id: Option<&Value>) -> String {
    match id {
        None => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// Whether a state is a proven route fault rather than a pending or unknown
/// outcome. Only these may file a transport edge or prescribe recovery.
#[must_use]
pub fn is_proven_fault(state: CorrelationAssessmentState) -> bool {
    matches!(
        state,
        CorrelationAssessmentState::HostRespondingStuckAfterDeadline
            | CorrelationAssessmentState::ResponseMisclassifiedByHost
            | CorrelationAssessmentState::TransportLostAfterFlush
    )
}

impl BridgeRunner {
    /// Submits one ELIOT emission observation through the OWNER's admitted
    /// event route and retains it for a later host-event join.
    ///
    /// This is the ELIOT-side producer. It records only what the stdio
    /// boundary directly observed — the correlation identity, the
    /// receive/handler/frame/emission stages, the exact byte and flush receipt,
    /// and the typed handler outcome — and files it under the correlation
    /// identity digest so the owner owns its durability, replay and
    /// idempotency exactly as it owns every other bridge event.
    ///
    /// It declares no host terminal state and no degradation. A successful
    /// emission produces a record whose assessment is pending; only a later
    /// admitted host event can resolve it, and only through
    /// [`Self::reconcile_terminal_host_event`].
    pub fn submit_emission_observation(
        &mut self,
        emission: &EliotEmissionObservation,
        canonical: CanonicalDisposition,
        binding: Option<OwnerValidatedOperationBinding>,
        deadline_unix_ms: Option<u64>,
    ) -> Result<CorrelationTrackOutcome, Box<BridgeError>> {
        let Some(view) = self.core.attach_view() else {
            return Err(Box::new(BridgeError::NotAttached));
        };
        let fence = view.binding().state_fence().clone();
        let generation = ResourceGeneration::new(fence.generation().get())
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        let digest = emission.identity.identity_digest.clone();
        let payload = serde_json::to_value(emission)
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        let envelope = EventEnvelope {
            stream_id: format!("{MCP_EMISSION_OWNER}.mcp-emissions"),
            producer_id: MCP_EMISSION_PRODUCER_ID.to_owned(),
            producer_generation: generation,
            authority_epoch: fence.authority_epoch().clone(),
            // The correlation identity digest IS the event identity. That is
            // what lets a later host event name this exact correlation, and
            // what makes a changed emission under a changed digest a different
            // event rather than a silent overwrite of this one.
            event_id: digest,
            // A correlation is a per-invocation commitment, not a stream
            // position, exactly like the retained effect decision.
            sequence: 1,
            causal_predecessor_refs: Vec::new(),
            delivery_class: DeliveryClass::DurableObservation,
            ack_required: true,
            payload_type: MCP_EMISSION_PAYLOAD_TYPE.to_owned(),
            payload_or_blob_ref: EventPayload::Inline(Box::new(ProtocolPayload::Json(payload))),
            state_fence: StateFence::new(fence.authority_epoch().clone(), generation),
            trace_context: std::collections::BTreeMap::new(),
        };
        envelope
            .validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        let status = self.core.forward_event(&envelope)?;
        let durable = !matches!(
            status,
            eliot_agent_bridge_core::EventForwardStatus::BestEffortForwarded
                | eliot_agent_bridge_core::EventForwardStatus::BestEffortGapSignalled { .. }
        );
        if !durable {
            // The owner did not make this durable, so the record is retained
            // only for this process's own join window and is never promoted to
            // a host fact.
            return Ok(CorrelationTrackOutcome::RotationDropped);
        }
        // The coverage floor is read from the owner's own journal HERE, at
        // admission, and recorded with the correlation. A later sweep compares
        // a proven interval against this recorded point instead of against
        // whatever the journal head happens to be by then, which is the only
        // form of the comparison that can be both strict and satisfiable.
        let required_seq = owner_observed_sequence(&self.core);
        Ok(self.correlations.track(TrackedCorrelation {
            emission: emission.clone(),
            assessments: AssessmentLog::default(),
            canonical,
            binding,
            deadline_unix_ms,
            required_seq,
        }))
    }

    /// Joins one admitted terminal host event onto the live owner and resolves
    /// the correlation the event names.
    ///
    /// The candidate is verified against the OWNER's own journal, attach
    /// binding and observed route before any assessment is derived, so a stale,
    /// foreign, duplicated, reordered or out-of-order event closes nothing
    /// current. Every expected set is owner-sourced: the journal is the
    /// owner's, the live generation is the owner's attach binding, the route is
    /// the owner's own observed fingerprint, and the prior accepted evidence is
    /// read back out of the correlation's own retained revisions.
    ///
    /// Each retained correlation is offered the candidate exactly once, in
    /// retention order, so one event cannot close one correlation twice and
    /// one correlation cannot close once per event. Retention order decides
    /// nothing: an acceptance means the host event's own invocation scope named
    /// that correlation, and if the event were ever to match more than one, the
    /// join refuses as [`ReconcileFailure::AmbiguousAttribution`] rather than
    /// taking the first. A later exact host-completion event therefore resolves
    /// the SAME correlation as completed and appends a linked revision, so no
    /// false degradation stays current beside a healthy completion.
    ///
    /// Nothing here nominates a correlation on the caller's behalf. The join
    /// keys carry no correlation digest and no invocation scope, because a
    /// value the correlation recorded says nothing about which event belongs to
    /// it; comparing it back would pass for every retained record and let a
    /// turn-level terminal fact close whichever request was still pending. The
    /// exact invocation is instead read back out of each retained emission's own
    /// immutable identity and matched against the host event's own minted
    /// invocation scope.
    ///
    /// #2899 A8 — the three event dispositions are separated here, not
    /// collapsed into "not attributable":
    ///
    /// * an **exact duplicate** (same event identity, byte-equal evidence) is
    ///   idempotent: the correlation's current verdict is reported unchanged,
    ///   nothing is appended, and no edge is re-filed, so repeated duplicates
    ///   cannot exhaust the bounded revision chain or mutate the record;
    /// * **changed content under the same event identity** is a conflict: it is
    ///   returned as [`ReconcileFailure::ContentConflict`] carrying both
    ///   digests, nothing is appended, and the prior accepted revision stands.
    ///   It is never a silent overwrite and never a last-write-wins;
    /// * a **stale generation** never reaches either case: the owner's own
    ///   normalizer refuses an event whose session is not the owner's live one,
    ///   so a rotated or restarted host closes nothing current.
    pub fn reconcile_terminal_host_event(
        &mut self,
        event: &HostEventEnvelope,
        integration_id: &str,
        now_unix_ms: u64,
    ) -> Result<HostEventReconciliation, ReconcileFailure> {
        if !attests_invocation_terminal(event) {
            return Ok(HostEventReconciliation::NotTerminal);
        }
        if self.core.attach_view().is_none() {
            return Err(ReconcileFailure::OwnerUnavailable);
        }
        let offer = self.offer_candidate_to_correlations(event, integration_id, now_unix_ms)?;
        // A conflict outranks an acceptance: it means the owner journal itself
        // holds two different contents under one event identity, or that a
        // correlation already accepted this identity with different content.
        // Either way the honest outcome is a refusal that closes nothing.
        if let Some(conflict) = offer.conflict {
            return Err(ReconcileFailure::ContentConflict(conflict));
        }
        let Some((index, assessment)) = offer.accepted else {
            return Ok(HostEventReconciliation::NoTrackedCorrelation);
        };
        self.apply_terminal_assessment(index, assessment, event)
    }

    /// Offers one candidate to every retained correlation and reports what the
    /// owner's join decided.
    ///
    /// Returns the single accepted `(index, assessment)` and any content
    /// conflict the join raised. A refusal means the event is not attributable
    /// to that correlation, which is the ordinary outcome for all of them; the
    /// loop never takes the first acceptance, it counts them, so a candidate
    /// that somehow matched more than one correlation is an explicit ambiguity
    /// refusal rather than a silent attribution to whichever record happened to
    /// be retained first. Correct attribution is the join's job — the host
    /// event's own invocation scope, or nothing.
    ///
    /// A content conflict is collected rather than skipped: the join already
    /// proved the event IS that correlation's, so treating the contradiction as
    /// a plain non-attribution would hide a refused mutation behind an ordinary
    /// "no tracked correlation".
    fn offer_candidate_to_correlations(
        &self,
        event: &HostEventEnvelope,
        integration_id: &str,
        now_unix_ms: u64,
    ) -> Result<CandidateOffer, ReconcileFailure> {
        let mut offer = CandidateOffer::default();
        let conflict = &mut offer.conflict;
        let accepted = &mut offer.accepted;
        for index in 0..self.correlations.records().len() {
            let request = {
                let record = &self.correlations.records()[index];
                TerminalReconcileRequest {
                    emission: &record.emission,
                    candidate: event,
                    keys: &HostEventJoinKeys {
                        integration_id: integration_id.to_owned(),
                        deadline_unix_ms: record.deadline_unix_ms,
                    },
                    assessments: &record.assessments,
                    operation_binding: record.binding.as_ref(),
                    canonical: &record.canonical,
                    ui_confirmed_stale: false,
                    now_unix_ms: Some(now_unix_ms),
                }
            };
            match reconcile_terminal_event(&self.core, &request) {
                Ok(assessment) => {
                    if accepted.is_some() {
                        return Err(ReconcileFailure::AmbiguousAttribution(
                            event.event_id.as_str().to_owned(),
                        ));
                    }
                    *accepted = Some((index, assessment));
                }
                Err(ReconcileError::PriorEvidenceConflict(replay)) => {
                    *conflict = Some(replay);
                }
                Err(ReconcileError::JournalContentConflict { event_id }) => {
                    *conflict = Some(ReplayConflict {
                        event_id,
                        prior_digest: String::new(),
                        candidate_digest: String::new(),
                    });
                }
                Err(_) => {}
            }
        }
        Ok(offer)
    }

    /// Applies one accepted assessment to the correlation that accepted it.
    ///
    /// The same event identity with byte-equal evidence is an exact replay, and
    /// the owner's own replay validator is the only thing that may say so. It is
    /// idempotent: the current record already states this verdict, so nothing is
    /// appended and the bounded chain cannot be exhausted by a repeated
    /// duplicate. A distinct event appends one linked revision that supersedes
    /// the previous one, so a healthy completion becomes the current record over
    /// an earlier degradation without any emitted byte changing.
    fn apply_terminal_assessment(
        &mut self,
        index: usize,
        assessment: Assessment,
        event: &HostEventEnvelope,
    ) -> Result<HostEventReconciliation, ReconcileFailure> {
        // Read before the mutable borrow: `owner_sequence` and the owner edge
        // read both need `&self`, and neither can be read while a `&mut` into
        // `self.correlations` is live.
        let sequence = self.correlations.owner_sequence(&self.core);
        let edge_present = self.owner_holds_edge(event.event_id.as_str());
        let digest = self.correlations.records()[index]
            .emission
            .identity
            .identity_digest
            .clone();
        let canonical = self.correlations.records()[index].canonical.clone();
        let record = &mut self.correlations.records_mut()[index];
        if let (Some(prior), Some(candidate)) = (
            record.assessments.latest_host_evidence(),
            // Borrowed, not moved: the assessment is still needed below to
            // derive the verdict this reconciliation reports, and the replay
            // validator only compares values.
            assessment.evidence.host_event.as_ref(),
        ) {
            match check_event_replay(prior, candidate) {
                Ok(HostEventReplay::ExactDuplicate) => {
                    let held = record.assessments.latest();
                    let current = held.map_or(assessment.state, |rev| rev.assessment.state);
                    return Ok(HostEventReconciliation::Resolved {
                        correlation_digest: digest.clone(),
                        state: current,
                        // The edge is read back from the owner rather than
                        // re-filed: a duplicate files nothing new, and the
                        // honest answer to "does the owner hold one" is what the
                        // owner holds.
                        edge_filed: edge_present,
                        verdict: CorrelationVerdict {
                            correlation_digest: digest,
                            state: current,
                            revision: held.map_or(0, |revision| revision.revision),
                            supersedes: held.and_then(|revision| revision.supersedes),
                            coverage: coverage_of(&assessment),
                            canonical_disposition: canonical,
                            recovery: recovery_of(&assessment),
                        },
                    });
                }
                Ok(HostEventReplay::Distinct) => {}
                Err(replay) => return Err(ReconcileFailure::ContentConflict(replay)),
            }
        }
        let state = assessment.state;
        // The revision number this append will carry, read from the log's own
        // length before the append so the reported supersession link is the one
        // the owner actually assigned.
        let revision_number =
            u32::try_from(record.assessments.revisions().len()).unwrap_or(u32::MAX);
        let supersedes = revision_number.checked_sub(1);
        let coverage = coverage_of(&assessment);
        let recovery = recovery_of(&assessment);
        record
            .assessments
            .append(&digest, assessment)
            .map_err(|error| ReconcileFailure::RevisionRefused(error.to_string()))?;
        // The appended revision is cloned out of the correlations store before
        // the bridge core is borrowed mutably: the two fields are disjoint, but a
        // live `&mut` into `self.correlations` across `&mut self.core` is a
        // borrow error, not a race.
        let latest = record.assessments.latest().cloned();
        let edge_filed = match latest.as_ref() {
            Some(revision) => {
                matches!(
                    submit_derived_fault(&mut self.core, revision, sequence),
                    FaultEdgeSubmission::Submitted
                )
            }
            None => false,
        };
        Ok(HostEventReconciliation::Resolved {
            correlation_digest: digest.clone(),
            state,
            edge_filed,
            verdict: CorrelationVerdict {
                correlation_digest: digest,
                state,
                revision: revision_number,
                supersedes,
                coverage,
                canonical_disposition: canonical,
                recovery,
            },
        })
    }

    /// Assesses every tracked correlation against its admitted deadline from
    /// the live owner journal, with no terminal event.
    ///
    /// Only an owner-proven complete interval past the admitted deadline
    /// establishes stuck. Every other denominator stays pending or unknown, and
    /// a gapped or rotated journal is never reported as a host fault.
    ///
    /// #2899 A2/A3/A8 — three refusals, all read from this correlation's own
    /// retained record and the owner's own live binding:
    ///
    /// * a **closed** correlation (its current revision is not pending) is left
    ///   alone. A completed invocation cannot become stuck, so re-assessing it
    ///   would append a degradation OVER a healthy completion and make a false
    ///   fault the current record;
    /// * a **stale generation** is refused: the correlation's recorded session
    ///   must still be the owner's live session, exactly as the terminal join
    ///   requires of an event's own lineage. A rotated or restarted host closes
    ///   nothing here either;
    /// * the coverage floor is the sequence **recorded at emission**, so a
    ///   contiguous run of other invocations' events cannot read as proof for
    ///   this correlation, and no floor at all stays `UNKNOWN`.
    pub fn sweep_correlation_deadlines(&mut self, now_unix_ms: u64) -> CorrelationSweepReport {
        let mut report = CorrelationSweepReport::default();
        let live_session = owner_live_session(&self.core);
        let candidate_count = self.correlations.records().len();
        for index in 0..candidate_count {
            // Read-only pre-checks first: both compare this correlation's own
            // recorded values against the owner's own live state, and neither
            // is derived from the request being swept.
            if self.correlations.records()[index]
                .assessments
                .latest()
                .is_some_and(|revision| !revision.assessment.state.is_pending())
            {
                report.already_closed = report.already_closed.saturating_add(1);
                continue;
            }
            let recorded_session = self.correlations.records()[index]
                .emission
                .identity
                .session_id
                .clone();
            if recorded_session.is_some() && recorded_session != live_session {
                report.stale_generation = report.stale_generation.saturating_add(1);
                continue;
            }
            let request = {
                let record = &self.correlations.records()[index];
                DeadlineSweepRequest {
                    emission: &record.emission,
                    deadline_unix_ms: record.deadline_unix_ms,
                    required_seq: record.required_seq,
                    operation_binding: record.binding.as_ref(),
                    canonical: &record.canonical,
                    now_unix_ms: Some(now_unix_ms),
                }
            };
            let assessment = reconcile_deadline_sweep(&self.core, &request);
            if assessment.state.is_pending() {
                continue;
            }
            // Read before the mutable borrow, for the same reason as in
            // `reconcile_terminal_host_event`.
            let sequence = self.correlations.owner_sequence(&self.core);
            let digest = self.correlations.records()[index]
                .emission
                .identity
                .identity_digest
                .clone();
            let canonical = self.correlations.records()[index].canonical.clone();
            let state = assessment.state;
            let coverage = coverage_of(&assessment);
            let recovery = recovery_of(&assessment);
            let record = &mut self.correlations.records_mut()[index];
            let revision_number =
                u32::try_from(record.assessments.revisions().len()).unwrap_or(u32::MAX);
            let supersedes = revision_number.checked_sub(1);
            if record.assessments.append(&digest, assessment).is_err() {
                continue;
            }
            // Cloned out for the same reason as in
            // `reconcile_terminal_host_event`: a live `&mut` into
            // `self.correlations` cannot cross `&mut self.core`.
            let latest = record.assessments.latest().cloned();
            if let Some(revision) = latest {
                let _ = submit_derived_fault(&mut self.core, &revision, sequence);
            }
            report.verdicts.push(CorrelationVerdict {
                correlation_digest: digest,
                state,
                revision: revision_number,
                supersedes,
                coverage,
                canonical_disposition: canonical,
                recovery,
            });
        }
        report
    }

    /// Bounded pending/completed/degraded counts over the CURRENT verdict of
    /// each retained correlation.
    ///
    /// The counts are a read of this process's own retained records, projected
    /// through the owner's own [`AssessmentSummary`]. They describe what is
    /// current, so a superseded degradation is not counted beside the healthy
    /// completion that replaced it.
    pub fn correlation_verdict_summary(&self) -> AssessmentSummary {
        self.correlations.current_summary()
    }

    /// Whether the owner's own journal holds a transport edge for one event.
    ///
    /// Read from the owner rather than remembered from the submission that
    /// filed it, so an idempotent replay reports the edge that actually exists
    /// instead of claiming a fresh filing it did not perform.
    fn owner_holds_edge(&self, event_id: &str) -> bool {
        self.core.terminal_reduction_inputs().is_some_and(|inputs| {
            inputs
                .edges()
                .iter()
                .any(|edge| edge.event_ref() == event_id)
        })
    }
}
