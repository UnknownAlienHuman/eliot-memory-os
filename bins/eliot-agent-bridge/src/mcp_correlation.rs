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
//! This module is a child of the crate root, so it can read
//! [`BridgeRunner`]'s private `core` field directly and join against the same
//! live owner the rest of the bridge uses. It adds no new owner, no parallel
//! journal, and no authority.

use eliot_agent_bridge_core::host_event::ToolOutcomeClass;
use eliot_agent_bridge_core::{
    AgentBridgeCore, Assessment, AssessmentLog, BridgeError, CanonicalDisposition, CommitEvidence,
    CorrelationAssessmentState, CorrelationIdentity, CorrelationIdentityParts, CorrelationStage,
    DeadlineSweepRequest, EliotEmissionObservation, EmissionCause, FaultEdgeSubmission,
    HandlerOutcome, HostEventEnvelope, HostEventJoinKeys, NormalizedHostEventPayload,
    OperationIdentity, OwnerValidatedOperationBinding, StdioEmissionReceipt,
    TerminalReconcileRequest, reconcile_deadline_sweep, reconcile_terminal_event,
    submit_derived_fault,
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
        /// Whether the owner filed a transport edge for the revision.
        edge_filed: bool,
    },
    /// The event is not terminal, so it closes no correlation.
    NotTerminal,
    /// The event is terminal, this process tracks at least one emission
    /// correlation, and none of them claimed it.
    ///
    /// This is the ordinary case for a host event that is not about one of the
    /// MCP invocations this process emitted, and it is never a fault. It
    /// requires a NON-EMPTY correlation store: "there was something to claim
    /// and none of it claimed this event" is a per-event fact about one
    /// observation, while "this process tracked no emission at all" is a fact
    /// about the join itself and is refused as
    /// [`ReconcileFailure::NoCorrelationTracked`] instead. Reporting the two
    /// identically would state an ordinary per-event outcome for a join that
    /// cannot run, which is the false proof claim A0.3 forbids.
    NoTrackedCorrelation,
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
    /// This process retained no emission correlation, so the join has no
    /// candidate set to offer the event at all.
    ///
    /// #2899: the correlation store is process-local to the bridge and its
    /// only writer is [`observe_mcp_emission`], which runs on the MCP stdio
    /// front door. A host event reaching this method through any other ingress
    /// therefore finds an empty store, and the join is structurally unable to
    /// resolve there no matter what the event carries. That is a different fact
    /// from "this event names no tracked correlation", and it is refused
    /// separately so the absence of the candidate set is never reported as an
    /// ordinary per-event outcome. It names no missing producer and proposes no
    /// placement: the front door that owns both sides of this join is an
    /// architecture-owner decision, and this variant is the typed evidence of
    /// its absence, not a substitute for it.
    NoCorrelationTracked,
    /// More than one retained correlation accepted the same candidate event.
    ///
    /// Attribution is decided by the host event's own invocation scope, so this
    /// cannot happen while that scope is exact. It is refused rather than
    /// resolved by retention order: picking the first record would attribute a
    /// host terminal fact to whichever request happened to still be pending.
    AmbiguousAttribution(String),
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
            Self::NoCorrelationTracked => formatter.write_str(
                "this process retained no emission correlation, so the event closed none",
            ),
            Self::AmbiguousAttribution(event_id) => write!(
                formatter,
                "host event {event_id} matched more than one correlation; it closes none"
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
            // Same identity. The owner refuses a changed replay under one
            // event identity before this point, so replacing the retained
            // record here cannot rewrite an accepted observation.
            *existing = record;
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
pub fn observe_mcp_emission(
    runner: &mut BridgeRunner,
    request: &Value,
    method: &str,
    tool_name: Option<&str>,
    outcome: StdioEmissionOutcome,
    deadline_unix_ms: Option<u64>,
) -> Result<CorrelationTrackOutcome, Box<BridgeError>> {
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
        false,
        &CommitEvidence {
            canonical_receipt_write_id: None,
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
        Ok(self.correlations.track(TrackedCorrelation {
            emission: emission.clone(),
            assessments: AssessmentLog::default(),
            canonical,
            binding,
            deadline_unix_ms,
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
    /// A process that retained no emission at all cannot offer the event
    /// anything, so it refuses with
    /// [`ReconcileFailure::NoCorrelationTracked`] instead of answering
    /// [`HostEventReconciliation::NoTrackedCorrelation`]. The store is
    /// process-local and written only by [`observe_mcp_emission`] on the MCP
    /// stdio front door, so this is the outcome on every ingress served by a
    /// different door. It is stated, not repaired: the front door that owns
    /// both sides is not named by the architecture and is not this method's to
    /// choose, so nothing here defaults a correlation, widens the join, or
    /// weakens a refusal to make the two sides meet.
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
        let candidate_count = self.correlations.records().len();
        // An empty candidate set is refused before the loop, not reported as
        // its outcome. Offering an event to zero correlations and then calling
        // the result "no tracked correlation claimed it" would assert an
        // ordinary per-event fact the join never tested, on every ingress whose
        // front door does not also run the MCP emission producer. Refusing here
        // keeps the per-event answer truthful for the doors where the candidate
        // set exists, and names the missing one everywhere else (A0.3: a false
        // proof claim is a hard boundary). No correlation is created, defaulted
        // or implied by this refusal.
        if candidate_count == 0 {
            return Err(ReconcileFailure::NoCorrelationTracked);
        }
        // Every retained correlation is offered the candidate and the join
        // decides; a refusal means the event is not attributable to that
        // correlation, which is the ordinary outcome for all of them. The loop
        // never takes the first acceptance: it counts them, so a candidate that
        // somehow matched more than one correlation is an explicit ambiguity
        // refusal rather than a silent attribution to whichever record happened
        // to be retained first. Correct attribution is the join's job — the
        // host event's own invocation scope, or nothing.
        let mut accepted: Option<(usize, Assessment)> = None;
        for index in 0..candidate_count {
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
            let Ok(assessment) = reconcile_terminal_event(&self.core, &request) else {
                continue;
            };
            if accepted.is_some() {
                return Err(ReconcileFailure::AmbiguousAttribution(
                    event.event_id.as_str().to_owned(),
                ));
            }
            accepted = Some((index, assessment));
        }
        let Some((index, assessment)) = accepted else {
            return Ok(HostEventReconciliation::NoTrackedCorrelation);
        };
        // Read before the mutable borrow: `owner_sequence` needs
        // `&self.correlations` and `&self.core`, and neither can be read while a
        // `&mut` into `self.correlations` is live.
        let sequence = self.correlations.owner_sequence(&self.core);
        let record = &mut self.correlations.records_mut()[index];
        let digest = record.emission.identity.identity_digest.clone();
        let state = assessment.state;
        record
            .assessments
            .append(&digest, assessment)
            .map_err(|error| ReconcileFailure::RevisionRefused(error.to_string()))?;
        // The appended revision is cloned out of the correlations store before
        // the bridge core is borrowed mutably: the two fields are disjoint, but a
        // live `&mut` into `self.correlations` across `&mut self.core` is a
        // borrow error, not a race.
        let latest = record.assessments.latest().cloned();
        let edge_filed = match latest {
            Some(revision) => {
                matches!(
                    submit_derived_fault(&mut self.core, &revision, sequence),
                    FaultEdgeSubmission::Submitted
                )
            }
            None => false,
        };
        Ok(HostEventReconciliation::Resolved {
            correlation_digest: digest,
            state,
            edge_filed,
        })
    }

    /// Assesses every tracked correlation against its admitted deadline from
    /// the live owner journal, with no terminal event.
    ///
    /// Only an owner-proven complete interval past the admitted deadline
    /// establishes stuck. Every other denominator stays pending or unknown, and
    /// a gapped or rotated journal is never reported as a host fault.
    pub fn sweep_correlation_deadlines(
        &mut self,
        now_unix_ms: u64,
    ) -> Vec<(String, CorrelationAssessmentState)> {
        let candidate_count = self.correlations.records().len();
        let mut swept = Vec::new();
        for index in 0..candidate_count {
            let request = {
                let record = &self.correlations.records()[index];
                DeadlineSweepRequest {
                    emission: &record.emission,
                    deadline_unix_ms: record.deadline_unix_ms,
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
            let record = &mut self.correlations.records_mut()[index];
            let digest = record.emission.identity.identity_digest.clone();
            if record
                .assessments
                .append(&digest, assessment.clone())
                .is_err()
            {
                continue;
            }
            // Cloned out for the same reason as in
            // `reconcile_terminal_host_event`: a live `&mut` into
            // `self.correlations` cannot cross `&mut self.core`.
            let latest = record.assessments.latest().cloned();
            if let Some(revision) = latest {
                let _ = submit_derived_fault(&mut self.core, &revision, sequence);
            }
            swept.push((digest, assessment.state));
        }
        swept
    }
}
