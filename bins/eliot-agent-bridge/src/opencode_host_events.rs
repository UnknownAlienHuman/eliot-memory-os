//! Production `/v1/host-events` port implementations over the existing
//! Agent Bridge → Kernel bridge-event route (issue #2898).
//!
//! [`BridgeHostEventAdmission`] implements
//! [`HostEventAdmission`](eliot_agent_opencode::HostEventAdmission) by
//! building the `EventEnvelope` from the validated submission plus live
//! owner state (attach binding task/fence/epoch/generation) and submitting
//! it through the bridge's existing `forward_event` operation; gaps go
//! through the existing `forward_gap` operation. No HTTP-private event
//! journal exists: durability, idempotency, handoff, and reconciliation
//! stay with ORS behind the same route every other bridge event uses.
//!
//! Owner-state join rules, enforced before any forward:
//!
//! * The attach binding must be live; otherwise the bridge is unavailable.
//! * The attach fence epoch and the introduction epoch must be the same
//!   authority; otherwise the introduction is stale.
//! * The attach fence nonce must equal the introduction fence observed at
//!   mint; fence movement fails closed.
//! * A claimed task must equal the live attach task, and gate/skipped
//!   submissions must claim the live task; otherwise the scope conflicts.
//!   Envelope generations come from the live attach fence, which is what
//!   the route's own binding coherence requires.
//!
//! The adapter holds `&mut BridgeRunner` on the bridge thread: the runner
//! composition is single-threaded, so the port is not `Send` and the
//! listener serves on a single-threaded runtime there. Moving admission
//! onto a main-loop channel is the named gap
//! `OPENCODE_BRIDGE_THREAD_INTEGRATION`.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_agent_bridge_core::{
    AckPhase, BridgeError, CoverageGap, EventDisposition, EventForwardStatus, GapDisposition,
};
use eliot_agent_opencode::{
    ActionGate, ActionGateDecision, ActionGateError, ActionGateRequest, CredentialResolver,
    EffectDecisionRecord, HOST_EVENTS_PAYLOAD_TYPE, HostEventAdmission, HostEventAdmissionError,
    HostEventAdmissionFailure, HostEventAdmissionReceipt, HostEventDelivery, HostEventGap,
    HostEventKind, HostEventPorts, HostEventSubmission, HostEventsBindError, HostEventsListener,
    HostEventsShutdown, IntroductionStore, LoopbackEndpoint,
};
use eliot_contracts::{EpochId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use eliot_governor::{GovernorActionGateRefusal, GovernorActionGateRequest, decide_pre_effect};
use eliot_integration_coverage::GovernanceProfile;
use eliot_process::{FencingToken, Generation, SecretRef};
use eliot_protocol::{DeliveryClass, EventEnvelope, EventPayload, ProtocolPayload};
use eliot_user_broker_core::{OpenCodeBridgeIntroduction, OpenCodeSessionFacts};
use secrecy::SecretString;
use thiserror::Error;

use crate::BridgeRunner;

/// Exact `EventEnvelope::payload_type` of a persisted effect-decision
/// commitment. It names the closed, versioned record the route admits, so a
/// decision is never confused with the retained host event it is bound to.
pub const HOST_EVENTS_DECISION_PAYLOAD_TYPE: &str = "opencode.effect-decision.v1";

/// Producer identity of a persisted effect-decision commitment. It is the
/// decision's own producer, distinct from the `OpenCode` plugin that produced
/// the retained event: a decision is made by the Governor through the bridge,
/// not by the host.
pub const HOST_EVENTS_DECISION_PRODUCER_ID: &str = "opencode.action-gate";

/// Reconciliation owner of an `OpenCode` effect decision: the existing
/// bridge-event route / ORS reconciliation owner named by
/// [`HOST_EVENTS_DECISION_RECONCILER`](eliot_agent_opencode::HOST_EVENTS_DECISION_RECONCILER).
/// It already holds the durable event and its ORS idempotency survives the
/// listener process lifecycle, so the decision record is admitted through the
/// same route rather than in a second journal.
pub const OPENCODE_DECISION_OWNER: &str = eliot_agent_opencode::HOST_EVENTS_DECISION_RECONCILER;

/// Narrow Governor/authority pre-effect evaluation over the live attach
/// binding (issue #2898, step 9).
///
/// The Governor is the pre-effect decision owner. This adapter holds the
/// current [`GovernanceProfile`](eliot_integration_coverage::GovernanceProfile)
/// the composition supplies and delegates the exact decision to
/// [`eliot_governor::decide_pre_effect`], which evaluates it through the
/// existing `GovernanceProfile::authorizes` primitive under the current
/// policy revision. No policy is decided in the HTTP handler, and a refused or
/// unconfigured Governor yields `recorded` — a durable observation that cannot
/// authorize a mutating tool.
pub struct GovernorActionGate<P> {
    current_profile: Option<P>,
}

impl<P> GovernorActionGate<P> {
    /// Builds the gate over the current Governor profile, or `None` when
    /// nothing has been derived (fail closed to `recorded`).
    #[must_use]
    pub fn new(current_profile: Option<P>) -> Self {
        Self { current_profile }
    }
}

impl<P> ActionGate for GovernorActionGate<P>
where
    P: Borrow<GovernanceProfile> + Send,
{
    fn decide(
        &mut self,
        _introduction: &OpenCodeBridgeIntroduction,
        receipt: &HostEventAdmissionReceipt,
        request: &ActionGateRequest,
    ) -> Result<ActionGateDecision, ActionGateError> {
        let governor_request = GovernorActionGateRequest {
            operation_id: request.operation_id.clone(),
            request_hash: request.request_hash.clone(),
            effect_digest: request.effect_digest.clone(),
            tool: request.tool.clone(),
            bridge_generation: request.bridge_generation,
            authority_epoch: request.authority_epoch.clone(),
            fence_id: request.fence_id.clone(),
        };
        let verdict = decide_pre_effect(
            self.current_profile.as_ref().map(Borrow::borrow),
            &governor_request,
            &receipt.authority_epoch,
            &receipt.fence_id,
            receipt.bridge_generation,
        );
        Ok(ActionGateDecision {
            request_hash: request.request_hash.clone(),
            allow: verdict.allow,
            policy_revision: verdict.policy_revision,
            authority_revision: verdict.authority_revision,
            // The Governor's decision carries no independent expiry; the
            // ingress accepts an `allow` only under a current expiry, so a
            // decision with none degrades to `recorded` rather than becoming
            // an unbounded permit.
            expires_at_ms: 0,
            decision_receipt: verdict.decision_receipt,
            reason_code: verdict.reason_code.map(GovernorActionGateRefusal::as_str),
        })
    }
}

/// Current-introduction holder for the bridge process.
///
/// The User Broker mints introductions; the bridge composition installs
/// the current one here with [`BridgeIntroductionStore::install`] (which
/// retires the replaced entry), refreshes the broker-observed session facts
/// with [`BridgeIntroductionStore::observe_session`], and retires the route
/// with [`BridgeIntroductionStore::revoke`] and
/// [`BridgeIntroductionStore::clear`] when the serving life ends.
///
/// Rotation, listener death, bridge restart, logout, and revocation
/// invalidate the old introduction before another request is admitted
/// through three live checks that need no supervisor: the installed
/// introduction's own issue/expiry window, the live revocation set, and
/// `BridgeHostEventAdmission`'s owner-state join, which re-proves the
/// introduction's Authority Epoch, `StateFence` nonce and bridge generation
/// against this process's live attach binding on every admitted event and
/// every committed decision. A foreign or stale listener cannot inherit the
/// route because the socket is bound exclusively on the port the
/// introduction pins and the ingress join refuses any other port.
#[derive(Clone, Debug, Default)]
pub struct BridgeIntroductionStore {
    current: Option<OpenCodeBridgeIntroduction>,
    revoked: HashSet<String>,
    facts: Option<OpenCodeSessionFacts>,
}

impl BridgeIntroductionStore {
    /// Creates an empty store: the route is unintroduced until
    /// [`BridgeIntroductionStore::install`] runs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the current introduction, replacing any previous one. The
    /// replaced introduction's revocation id is retired as part of the
    /// install, so endpoint replacement and rotation invalidate the old
    /// introduction before another request by construction: even a holder
    /// of the previous value fails the live revocation check.
    pub fn install(&mut self, introduction: OpenCodeBridgeIntroduction) {
        if let Some(previous) = self.current.replace(introduction) {
            self.revoked.insert(previous.revocation_id);
        }
    }

    /// Retires one revocation id. Revoked introductions fail closed even
    /// when still installed and inside their window.
    pub fn revoke(&mut self, revocation_id: &str) {
        self.revoked.insert(revocation_id.to_owned());
    }

    /// Records live broker-observed session facts for the session probe.
    pub fn observe_session(&mut self, facts: OpenCodeSessionFacts) {
        self.facts = Some(facts);
    }

    /// Clears the installed introduction and facts (logout/restart path).
    pub fn clear(&mut self) {
        self.current = None;
        self.facts = None;
    }
}

impl IntroductionStore for BridgeIntroductionStore {
    fn current_introduction(&self) -> Option<OpenCodeBridgeIntroduction> {
        self.current.clone()
    }

    fn is_revoked(&self, revocation_id: &str) -> bool {
        self.revoked.contains(revocation_id)
    }

    fn session_facts(&self) -> OpenCodeSessionFacts {
        self.facts.clone().unwrap_or(OpenCodeSessionFacts {
            installation_id: String::new(),
            windows_sid: String::new(),
            interactive_session_id: String::new(),
            broker_generation: Generation::default(),
            bridge_generation: Generation::default(),
            launch_nonce: String::new(),
            executable_digest: String::new(),
        })
    }

    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(u64::MAX)
    }
}

/// Credential resolution refusal. Carries no secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum FnCredentialError {
    /// The owner refused or could not resolve the handle.
    #[error("credential resolution refused")]
    Refused,
}

/// Owner-provided credential resolver over a closure.
///
/// The closure is supplied by the process owner at composition time and
/// resolves the introduction's opaque [`SecretRef`] through the owner's
/// own secret boundary. Only the physical User Broker/process owner may
/// introduce the short-lived secret, and solely to the exact approved
/// `OpenCode` process.
pub struct FnCredentialResolver<F> {
    resolve: F,
}

impl<F> FnCredentialResolver<F>
where
    F: Fn(&SecretRef) -> Option<SecretString> + Send,
{
    /// Builds a resolver over the owner-supplied closure.
    pub fn new(resolve: F) -> Self {
        Self { resolve }
    }
}

impl<F> CredentialResolver for FnCredentialResolver<F>
where
    F: Fn(&SecretRef) -> Option<SecretString> + Send,
{
    type Error = FnCredentialError;

    fn resolve(&self, handle: &SecretRef) -> Result<SecretString, Self::Error> {
        (self.resolve)(handle).ok_or(FnCredentialError::Refused)
    }
}

/// Builds the admission receipt for one committed effect decision.
///
/// The owner-state bindings come from the live attach fence the decision was
/// admitted under, never reconstructed from the record. `stored` is the
/// OWNER's persisted record for this operation identity, and it is supplied
/// only when the route's own idempotency proved that by answering `Duplicate`
/// for these exact canonical bytes; a freshly written decision passes `None`.
/// The receipt's `replayed` flag and `duplicate` disposition are therefore
/// both derived from that same owner answer, so the handler never reconciles a
/// first evaluation against itself and never learns a stored record from
/// process memory.
fn decision_receipt(
    stream_id: String,
    event_id: String,
    epoch: EpochId,
    fence: &FencingToken,
    stored: Option<EffectDecisionRecord>,
) -> HostEventAdmissionReceipt {
    let replayed = stored.is_some();
    HostEventAdmissionReceipt {
        stream_id,
        event_id,
        phase: phase_text(AckPhase::Durable).to_owned(),
        disposition: if replayed { "duplicate" } else { "accepted" }.to_owned(),
        envelope_digest: stored
            .as_ref()
            .map_or_else(String::new, |record| record.decision_receipt.clone()),
        replayed,
        cursor_advanced: false,
        authority_epoch: epoch,
        fence_id: fence.nonce().to_owned(),
        bridge_generation: fence.generation().get(),
        replayed_decision: stored,
    }
}

fn phase_text(phase: AckPhase) -> &'static str {
    match phase {
        AckPhase::Received => "RECEIVED",
        AckPhase::Durable => "DURABLE",
        AckPhase::Normalized => "NORMALIZED",
        AckPhase::Applied => "APPLIED",
        AckPhase::Rejected => "REJECTED",
        AckPhase::Unknown => "UNKNOWN",
    }
}

fn disposition_text(disposition: EventDisposition) -> &'static str {
    match disposition {
        EventDisposition::Accepted => "accepted",
        EventDisposition::Duplicate => "duplicate",
        EventDisposition::Rejected => "rejected",
        EventDisposition::Conflict => "conflict",
    }
}

/// Maps one route failure onto the admission's typed refusal.
///
/// [`BridgeError::InvalidEventDisposition`] carrying
/// [`EventDisposition::Conflict`] is the route's **determined** changed-content
/// refusal, not a transport problem: the owner compared this exact envelope's
/// canonical bytes against the stored row it holds and they differ. It is the
/// only `BridgeError` whose meaning is a decision rather than an inability, so
/// it keeps its own typed class here instead of being flattened into
/// `Unavailable`. Every other route failure stays `Unavailable` unless the
/// owner named a fence.
fn bridge_failure(error: &BridgeError) -> HostEventAdmissionFailure {
    match error {
        BridgeError::StaleAuthority | BridgeError::ExternalAttachReconciliationRequired => {
            HostEventAdmissionFailure::Fenced
        }
        BridgeError::InvalidEventDisposition(EventDisposition::Conflict) => {
            HostEventAdmissionFailure::Conflict
        }
        _ => HostEventAdmissionFailure::Unavailable,
    }
}

/// Existing bridge-event route behind the ingress admission port.
///
/// Holds the live [`BridgeRunner`] by exclusive reference on the bridge
/// thread and nowhere else. See the module documentation for the
/// owner-state join rules.
pub struct BridgeHostEventAdmission<'runner> {
    runner: &'runner mut BridgeRunner,
    /// Process-local **candidate** set of the effect decisions this admission
    /// has already put through the route, keyed by their exact operation
    /// identity.
    ///
    /// This is a hint and never the authority. It exists only so a retry
    /// served by the same process can *re-present* the exact bytes without
    /// rebuilding them, and it is emptied by a bridge restart. A record leaves
    /// this set towards [`HostEventAdmissionReceipt::replayed_decision`] only
    /// after the owner's durable route answered `Duplicate` for those exact
    /// canonical bytes, so process memory can never make a replayed decision
    /// appear. The authority is always the OWNER's persisted row: the route's
    /// own ORS idempotency answers `Duplicate` only when the presented
    /// envelope matches the stored durable one in identity, sequence, producer,
    /// generation, authority epoch, representation and provenance, which is
    /// what makes that answer a read-back of what was actually persisted.
    committed_decisions: BTreeMap<String, EffectDecisionRecord>,
}

impl<'runner> BridgeHostEventAdmission<'runner> {
    /// Borrows the live runner for same-thread admission.
    pub fn new(runner: &'runner mut BridgeRunner) -> Self {
        Self {
            runner,
            committed_decisions: BTreeMap::new(),
        }
    }

    fn check_coherence(
        &self,
        introduction: &OpenCodeBridgeIntroduction,
        submission: &HostEventSubmission,
    ) -> Result<FencingToken, HostEventAdmissionError> {
        let binding = self
            .runner
            .attach_view()
            .map(|view| view.binding().clone())
            .ok_or_else(|| HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable))?;
        let fence = binding.state_fence().clone();
        if !fence
            .authority_epoch()
            .is_same_authority(&introduction.authority_epoch)
        {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::StaleEpoch,
            ));
        }
        if fence.nonce() != introduction.fence_id {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Fenced,
            ));
        }
        let live_task = binding.task_binding().task_id().as_str();
        let task_bound = matches!(
            submission.kind,
            HostEventKind::Gate | HostEventKind::Skipped
        );
        if submission
            .task_id
            .as_deref()
            .is_some_and(|task| task != live_task)
            || (task_bound && submission.task_id.is_none())
        {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::ScopeConflict,
            ));
        }
        Ok(fence)
    }

    /// Returns whether one decision record is still bound to the live attach
    /// fence. A decision made under a fence, generation or authority that has
    /// since moved must never be re-presented or persisted: the write would
    /// bind stale owner state.
    fn decision_binds_live_fence(record: &EffectDecisionRecord, fence: &FencingToken) -> bool {
        fence.nonce() == record.fence_id && fence.generation().get() == record.bridge_generation
    }

    /// Builds the durable decision envelope for one record under the live
    /// attach fence, through the same closed, versioned payload type every
    /// effect-decision commitment uses.
    fn decision_envelope(
        record: &EffectDecisionRecord,
        epoch: &EpochId,
    ) -> Result<EventEnvelope, HostEventAdmissionError> {
        let generation = ResourceGeneration::new(record.bridge_generation)
            .map_err(|_| HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable))?;
        let envelope = EventEnvelope {
            stream_id: format!("{OPENCODE_DECISION_OWNER}.decisions"),
            producer_id: HOST_EVENTS_DECISION_PRODUCER_ID.to_owned(),
            producer_generation: generation,
            authority_epoch: epoch.clone(),
            event_id: record.operation_id.clone(),
            // A decision is a per-operation commitment, not a stream position;
            // its own content is what identifies it.
            sequence: 1,
            causal_predecessor_refs: Vec::new(),
            delivery_class: DeliveryClass::DurableControl,
            ack_required: true,
            payload_type: HOST_EVENTS_DECISION_PAYLOAD_TYPE.to_owned(),
            payload_or_blob_ref: EventPayload::Inline(Box::new(ProtocolPayload::Json(
                record.to_json(),
            ))),
            state_fence: StateFence::new(epoch.clone(), generation),
            trace_context: BTreeMap::new(),
        };
        envelope
            .validate()
            .map_err(|_| HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable))?;
        Ok(envelope)
    }

    /// Reads the OWNER's persisted decision for one exact operation identity.
    ///
    /// This is the durable read-back, and it is the only way a stored record
    /// reaches a receipt. A candidate this process already produced is
    /// re-presented through the same bridge-event route the decision is
    /// committed on, and the record is returned **only** when the route's own
    /// idempotency answers `Duplicate` for those exact canonical bytes — the
    /// owner's proof that its durable row holds precisely this persisted
    /// content. `None` means the owner holds nothing for this identity, and
    /// changed content under a known identity is the determined
    /// [`HostEventAdmissionFailure::Conflict`] carried by `bridge_failure`,
    /// never an `Unavailable` and never a second record.
    ///
    /// A candidate that the owner does not hold yet is made durable by this
    /// call, which is the completion of a write whose response was lost inside
    /// this same process — not a new decision, and never a second one.
    fn read_back_persisted_decision(
        &mut self,
        record: &EffectDecisionRecord,
        epoch: &EpochId,
        fence: &FencingToken,
    ) -> Result<Option<EffectDecisionRecord>, HostEventAdmissionError> {
        if !Self::decision_binds_live_fence(record, fence) {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Fenced,
            ));
        }
        let envelope = Self::decision_envelope(record, epoch)?;
        let status = self
            .runner
            .forward_event(&envelope)
            .map_err(|error| HostEventAdmissionError::of(bridge_failure(&error)))?;
        let EventForwardStatus::Durable {
            phase, disposition, ..
        } = status
        else {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Unavailable,
            ));
        };
        if !matches!(
            phase,
            AckPhase::Durable | AckPhase::Normalized | AckPhase::Applied
        ) {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Unavailable,
            ));
        }
        Ok(matches!(disposition, EventDisposition::Duplicate).then(|| record.clone()))
    }
}

impl HostEventAdmission for BridgeHostEventAdmission<'_> {
    fn admit(
        &mut self,
        introduction: &OpenCodeBridgeIntroduction,
        submission: &HostEventSubmission,
    ) -> Result<HostEventAdmissionReceipt, HostEventAdmissionError> {
        let fence = self.check_coherence(introduction, submission)?;
        let epoch = fence.authority_epoch().clone();
        let generation_value = fence.generation().get();
        let resource_generation = ResourceGeneration::new(generation_value)
            .map_err(|_| HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable))?;
        let delivery_class = match submission.delivery {
            HostEventDelivery::Control => DeliveryClass::DurableControl,
            HostEventDelivery::Observation => DeliveryClass::DurableObservation,
        };
        let envelope = EventEnvelope {
            stream_id: submission.stream_id.clone(),
            producer_id: submission.producer_id.clone(),
            producer_generation: resource_generation,
            authority_epoch: epoch.clone(),
            event_id: submission.event_id.clone(),
            sequence: submission.sequence,
            causal_predecessor_refs: Vec::new(),
            delivery_class,
            ack_required: true,
            payload_type: HOST_EVENTS_PAYLOAD_TYPE.to_owned(),
            payload_or_blob_ref: EventPayload::Inline(Box::new(ProtocolPayload::Json(
                submission.envelope_json.clone(),
            ))),
            state_fence: StateFence::new(epoch.clone(), resource_generation),
            trace_context: BTreeMap::new(),
        };
        envelope
            .validate()
            .map_err(|_| HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable))?;
        let envelope_digest = canonical_json_bytes(&envelope)
            .map(|canonical| sha256_hex(&canonical))
            .map_err(|_| HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable))?;
        let status = self
            .runner
            .forward_event(&envelope)
            .map_err(|error| HostEventAdmissionError::of(bridge_failure(&error)))?;
        match status {
            EventForwardStatus::Durable {
                phase,
                disposition,
                cursor_advanced,
            } => {
                if matches!(disposition, EventDisposition::Rejected) {
                    return Err(HostEventAdmissionError::of(
                        HostEventAdmissionFailure::Fenced,
                    ));
                }
                // A `Conflict` disposition never reaches here: the core route
                // converts it to `BridgeError::InvalidEventDisposition` before
                // it builds a status, so `bridge_failure` on the
                // `forward_event` line above already carries that determined
                // refusal through as `HostEventAdmissionFailure::Conflict`. The
                // stored digest is never exposed to a conflicting presenter; it
                // reconciles by replaying its original bytes under the same
                // identity.
                if !matches!(
                    phase,
                    AckPhase::Durable | AckPhase::Normalized | AckPhase::Applied
                ) {
                    return Err(HostEventAdmissionError::of(
                        HostEventAdmissionFailure::Unavailable,
                    ));
                }
                let candidate = self.committed_decisions.get(&submission.event_id).cloned();
                let replayed_decision = match candidate {
                    // The durable read-back. The retained event carries no
                    // decision yet, so the only question this admission can
                    // answer for the handler is whether the OWNER already
                    // persists a decision for this exact operation identity —
                    // and it may answer that only by re-presenting the bytes
                    // and taking the route's own `Duplicate`. A candidate that
                    // survives that proof is the persisted decision, so a retry
                    // served by this process takes the replay branch and the
                    // `ActionGate` is never consulted a second time. With no
                    // candidate in hand there is nothing to re-present, and the
                    // owner alone decides the outcome on the commit below.
                    Some(candidate) => {
                        self.read_back_persisted_decision(&candidate, &epoch, &fence)?
                    }
                    None => None,
                };
                let admitted = HostEventAdmissionReceipt {
                    stream_id: submission.stream_id.clone(),
                    event_id: submission.event_id.clone(),
                    phase: phase_text(phase).to_owned(),
                    disposition: disposition_text(disposition).to_owned(),
                    envelope_digest,
                    replayed: matches!(disposition, EventDisposition::Duplicate),
                    cursor_advanced,
                    authority_epoch: epoch,
                    fence_id: fence.nonce().to_owned(),
                    bridge_generation: generation_value,
                    replayed_decision,
                };
                // #2899: the event is now in the owner's live journal, so a
                // terminal invocation can be joined against the correlation it
                // names. This is the competent host evidence the correlation was
                // waiting for; nothing before this point could have resolved it.
                Self::reconcile_admitted_event(self, submission, &admitted);
                Ok(admitted)
            }
            EventForwardStatus::BestEffortForwarded
            | EventForwardStatus::BestEffortGapSignalled { .. } => Err(
                HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable),
            ),
        }
    }

    fn commit_decision(
        &mut self,
        record: &EffectDecisionRecord,
    ) -> Result<HostEventAdmissionReceipt, HostEventAdmissionError> {
        let binding = self
            .runner
            .attach_view()
            .map(|view| view.binding().clone())
            .ok_or_else(|| HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable))?;
        let fence = binding.state_fence().clone();
        let epoch = fence.authority_epoch().clone();
        // The decision must still be bound to the live owner state: a fence,
        // generation or authority that moved after the evaluation refuses the
        // write rather than persisting a decision under stale bindings.
        if !Self::decision_binds_live_fence(record, &fence) {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Fenced,
            ));
        }
        let stream_id = format!("{OPENCODE_DECISION_OWNER}.decisions");
        let event_id = record.operation_id.clone();
        // The route is asked every time, never a process-memory short cut: a
        // stored decision may only be reported because the OWNER's idempotency
        // proved these exact canonical bytes are the ones it persisted. A
        // candidate held in memory buys nothing here that the owner does not
        // already prove, so it cannot answer for the route even inside one
        // process.
        let envelope = Self::decision_envelope(record, &epoch)?;
        let status = self
            .runner
            .forward_event(&envelope)
            .map_err(|error| HostEventAdmissionError::of(bridge_failure(&error)))?;
        let EventForwardStatus::Durable {
            phase, disposition, ..
        } = status
        else {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Unavailable,
            ));
        };
        // Same-identity/different-content never reaches this arm: the core route
        // turns `Conflict` into `BridgeError::InvalidEventDisposition` before it
        // builds a status, so the determined refusal is already carried by the
        // `bridge_failure` mapping on the line above. The stored record is
        // deliberately not disclosed to a conflicting presenter; it reconciles
        // by replaying its own original content under the same identity.
        if !matches!(
            phase,
            AckPhase::Durable | AckPhase::Normalized | AckPhase::Applied
        ) {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Unavailable,
            ));
        }
        // The OWNER's durable row is the authority on this outcome, and its
        // `Duplicate` answer is the read-back of what was actually persisted.
        //
        // The route compares the stored row's envelope digest, sequence,
        // producer, generation, authority epoch, representation and provenance
        // against these exact presented bytes and answers `Duplicate` only when
        // every leg agrees; any difference is the determined conflict carried by
        // `bridge_failure`. So on `Duplicate` the presented record *is* the
        // record the owner holds, byte for byte, and it is returned as the
        // persisted decision: one durable event, one durable decision, no
        // second durable write, and never an `Unavailable` — so an exact retry
        // or a lost response that crosses a bridge restart reconciles the
        // original decision instead of failing closed with a retryable 503.
        let replayed = matches!(disposition, EventDisposition::Duplicate);
        // The record is retained only as a candidate to re-present; a later
        // report of it still requires the owner's `Duplicate`.
        self.committed_decisions
            .insert(event_id.clone(), record.clone());
        // A fresh write proves no replay happened, so it reports no replayed
        // decision. Returning the just-written record here would make the
        // handler reconcile a first evaluation against itself and report
        // `replayed: true` for a decision that was never replayed.
        let replayed_decision = if replayed { Some(record.clone()) } else { None };
        Ok(decision_receipt(
            stream_id,
            event_id,
            epoch,
            &fence,
            replayed_decision,
        ))
    }

    fn report_gap(
        &mut self,
        _introduction: &OpenCodeBridgeIntroduction,
        gap: &HostEventGap,
    ) -> Result<(), HostEventAdmissionError> {
        let coverage = CoverageGap {
            gap_id: gap.gap_id.clone(),
            obligation_profile_ref: "opencode.host-events.v1:passive-observation".to_owned(),
            reason_ref: gap.reason_ref.clone(),
            affected_interval: None,
            disposition: GapDisposition::DegradeDependentGuarantees,
            protected: false,
            evidence_refs: vec![gap.event_id.clone()],
        };
        coverage
            .validate()
            .map_err(|_| HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable))?;
        self.runner
            .forward_gap(&coverage)
            .map_err(|error| HostEventAdmissionError::of(bridge_failure(&error)))?;
        Ok(())
    }
}

impl BridgeHostEventAdmission<'_> {
    /// Joins a just-admitted terminal host event onto the correlation it names.
    ///
    /// #2899: the host event is now in the OWNER's live journal, so this is
    /// the first point at which a competent host terminal state exists. The
    /// join verifies the candidate against that journal, the owner's attach
    /// binding and the owner's observed route before deriving anything, so a
    /// stale, foreign, duplicated or reordered event closes nothing current.
    ///
    /// A reconciliation failure never fails the admission: the host event is
    /// already durable, and refusing to admit it because a correlation could
    /// not be closed would discard a competent observation. The failure is
    /// reported on stderr instead.
    fn reconcile_admitted_event(
        &mut self,
        submission: &HostEventSubmission,
        receipt: &HostEventAdmissionReceipt,
    ) {
        let Some(inputs) = self.runner.terminal_reduction_inputs() else {
            return;
        };
        let Some(journaled) = inputs
            .history()
            .iter()
            .find(|event| event.event_id.as_str() == receipt.event_id.as_str())
        else {
            return;
        };
        let now = crate::mcp_correlation::owner_now_unix_ms().unwrap_or(0);
        let outcome =
            self.runner
                .reconcile_terminal_host_event(journaled, &submission.producer_id, now);
        let (correlation_digest, state, edge_filed, failure) = match outcome {
            Ok(crate::mcp_correlation::HostEventReconciliation::Resolved {
                correlation_digest,
                state,
                edge_filed,
            }) => (
                correlation_digest,
                state.as_str(),
                edge_filed,
                String::new(),
            ),
            Ok(crate::mcp_correlation::HostEventReconciliation::NotTerminal) => {
                (String::new(), "not_terminal", false, String::new())
            }
            Ok(crate::mcp_correlation::HostEventReconciliation::NoTrackedCorrelation) => (
                String::new(),
                "no_tracked_correlation",
                false,
                String::new(),
            ),
            Err(error) => (String::new(), "unreconciled", false, error.to_string()),
        };
        tracing::info!(
            host_event_id = %receipt.event_id,
            correlation_digest = %correlation_digest,
            assessment_state = state,
            transport_edge_filed = edge_filed,
            reconcile_failure = %failure,
            "mcp host-event correlation reconciliation"
        );
    }
}

/// Assembles the ingress ports over the live bridge composition.
///
/// The admission port borrows the runner on the bridge thread; the gate is the
/// real Governor/authority evaluation
/// ([`GovernorActionGate`]) over the current policy profile the composition
/// supplies, so `tool.execute.before` is decided by the pre-effect decision
/// owner and never inside the HTTP handler. `current_profile` is `None` when no
/// Governor profile has been derived: the gate then refuses closed and the
/// response stays an observation-only `recorded`. Introductions and
/// credentials come from the owner's live store and secret boundary.
pub fn assemble_ports<F>(
    runner: &mut BridgeRunner,
    store: BridgeIntroductionStore,
    current_profile: Option<GovernanceProfile>,
    resolve_credential: F,
) -> HostEventPorts<
    BridgeHostEventAdmission<'_>,
    GovernorActionGate<GovernanceProfile>,
    BridgeIntroductionStore,
    FnCredentialResolver<F>,
>
where
    F: Fn(&SecretRef) -> Option<SecretString> + Send,
{
    HostEventPorts {
        admission: BridgeHostEventAdmission::new(runner),
        gate: GovernorActionGate::new(current_profile),
        introductions: store,
        credentials: FnCredentialResolver::new(resolve_credential),
    }
}

/// Startup disposition of the supervised `/v1/host-events` service.
///
/// The service is admitted only from [`HostEventsStartup::Introduced`]: an
/// unintroduced composition never binds a port, so the route cannot be
/// reachable without a User Broker-issued introduction naming the exact
/// endpoint this process would serve.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostEventsStartup {
    /// The owner installed a current introduction for the exact endpoint this
    /// process will own; the service may be started.
    Introduced {
        /// Exact loopback port the owner pinned for this bridge incarnation.
        port: u16,
        /// Bridge generation the introduction is bound to; the listener stops
        /// when the live generation moves away from it.
        bound_generation: u64,
    },
    /// No current introduction is installed, so nothing is served and no
    /// socket is opened.
    Unintroduced,
}

/// Resolves the startup disposition of the supervised `/v1/host-events`
/// service from the owner's current introduction.
///
/// The port and bound generation are read from the installed introduction —
/// never from a command-line value, an environment entry, or a constant — so
/// the route is admitted only when the User Broker has already named the
/// exact endpoint this bridge incarnation will own. An unintroduced
/// composition resolves [`HostEventsStartup::Unintroduced`] and no socket is
/// ever opened.
///
/// This is the composition decision itself, so it is `pub`: the package-local
/// wiring/negative proof `bins/AGENTS.md` requires reaches the same resolver
/// the shipped front door uses instead of a second implementation of it.
#[must_use]
pub fn host_events_startup(
    store: &BridgeIntroductionStore,
) -> Result<HostEventsStartup, HostEventsServiceError> {
    let Some(introduction) = store.current_introduction() else {
        return Ok(HostEventsStartup::Unintroduced);
    };
    let port = LoopbackEndpoint::parse(&introduction.endpoint)
        .map_err(|_| HostEventsServiceError::EndpointNotLoopback)?
        .port();
    Ok(HostEventsStartup::Introduced {
        port,
        bound_generation: introduction.bridge_generation.get(),
    })
}

/// Failure of the supervised `/v1/host-events` service (issue #2898).
///
/// Each variant is terminal and typed; no secret material, no caller value
/// and no server prose is carried.
#[derive(Debug, Error)]
pub enum HostEventsServiceError {
    /// No current introduction is installed, so the route stays closed.
    #[error("host-events route is not introduced: the User Broker owns no current introduction")]
    Unintroduced,
    /// The introduction does not name a canonical loopback endpoint, so the
    /// process cannot claim the port the owner reserved for it.
    #[error("introduction endpoint is not a canonical loopback endpoint")]
    EndpointNotLoopback,
    /// The exclusively-owned loopback socket could not be obtained.
    #[error("host-events listener bind failed: {0}")]
    Bind(#[from] HostEventsBindError),
    /// The single-threaded serving runtime could not be constructed.
    #[error("host-events serving runtime could not be constructed: {0}")]
    Runtime(#[source] std::io::Error),
}

/// Supervises `POST /v1/host-events` for the whole life of the bridge
/// process (issue #2898, steps 1, 4, 5 and 14).
///
/// The route is served only when the User Broker-issued introduction is
/// already installed in `store`, and only on the port that introduction
/// pins. The socket is obtained exclusively by this process through
/// [`HostEventsListener::bind_loopback`], which binds it and re-proves the
/// loopback address and the explicit non-zero port; a competing listener
/// cannot inherit the route, because a bind conflict is a refusal. Every
/// admitted request is additionally joined against this listener's own bound
/// port by the handler's `join_introduction` ownership check.
///
/// The stop and generation senders are held for the whole serving life, so a
/// dropped supervisor channel can never be mistaken for a supervised stop:
/// [`HostEventsListener::serve_until`] observes a channel closure as
/// [`HostEventsShutdown::Rotated`], and the returned
/// [`HostEventsShutdown`] is returned here as the real typed shutdown rather
/// than discarded. An unintroduced composition returns
/// [`HostEventsServiceError::Unintroduced`] without binding a port at all.
pub fn serve_host_events<F>(
    runner: &mut BridgeRunner,
    store: BridgeIntroductionStore,
    current_profile: Option<GovernanceProfile>,
    resolve_credential: F,
    stop: tokio::sync::watch::Receiver<bool>,
    active_generation: tokio::sync::watch::Receiver<u64>,
) -> Result<HostEventsShutdown, HostEventsServiceError>
where
    F: Fn(&SecretRef) -> Option<SecretString> + Send,
{
    let (port, bound_generation) = match host_events_startup(&store)? {
        HostEventsStartup::Introduced {
            port,
            bound_generation,
        } => (port, bound_generation),
        HostEventsStartup::Unintroduced => return Err(HostEventsServiceError::Unintroduced),
    };
    // `bind_loopback` both binds the socket and wraps it, re-proving the
    // loopback address and refusing a zero port. Wrapping it a second time via
    // `from_pre_bound` would bind a second socket and leave the first one
    // owned by nobody.
    let listener = HostEventsListener::bind_loopback(port)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(HostEventsServiceError::Runtime)?;
    let mut ports = assemble_ports(runner, store, current_profile, resolve_credential);
    Ok(runtime.block_on(listener.serve_until(
        &mut ports,
        bound_generation,
        stop,
        active_generation,
    )))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A refusal case for the determined same-identity/changed-content answer:
    /// the route's conflict must stay a conflict, never degrade into the
    /// retryable `Unavailable` class that would answer 503 and invite the
    /// client to resubmit content the owner already refused.
    #[test]
    fn route_conflict_stays_a_determined_conflict() {
        let failure = bridge_failure(&BridgeError::InvalidEventDisposition(
            EventDisposition::Conflict,
        ));
        assert_eq!(failure, HostEventAdmissionFailure::Conflict);
        let rejection = HostEventAdmissionError::of(failure).reject();
        assert_eq!(rejection.status, 409);
        assert_eq!(rejection.reason_code, "IDENTITY_CONFLICT");
    }

    /// The positive case: a fence named by the owner keeps its own typed class,
    /// and an ordinary route failure is still `Unavailable`, so this one change
    /// widens no other mapping into a conflict.
    #[test]
    fn only_the_determined_conflict_becomes_a_conflict() {
        for fenced in [
            BridgeError::StaleAuthority,
            BridgeError::ExternalAttachReconciliationRequired,
        ] {
            assert_eq!(
                bridge_failure(&fenced),
                HostEventAdmissionFailure::Fenced,
                "an owner-named fence must not be reclassified as a conflict"
            );
        }
        for unavailable in [
            BridgeError::NotAttached,
            BridgeError::AckIdentityMismatch,
            BridgeError::MissingDurableAck,
            BridgeError::InvalidEventDisposition(EventDisposition::Rejected),
        ] {
            assert_eq!(
                bridge_failure(&unavailable),
                HostEventAdmissionFailure::Unavailable,
                "only a determined conflict may become a conflict"
            );
        }
    }
}
