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
/// retires the replaced entry), retires out-of-band revocations with
/// [`BridgeIntroductionStore::revoke`], and refreshes live session facts
/// with [`BridgeIntroductionStore::observe_session`]. Rotation, listener
/// death, bridge restart, logout, and revocation invalidate the old
/// introduction here before another request is admitted.
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

    /// Rotates to a new introduction and refreshes the live session facts
    /// together. Runs on the bridge thread between requests: the replaced
    /// introduction is revoked by [`BridgeIntroductionStore::install`]
    /// before the new facts admit traffic under the new generation.
    pub fn rotate(
        &mut self,
        introduction: OpenCodeBridgeIntroduction,
        facts: OpenCodeSessionFacts,
    ) {
        self.install(introduction);
        self.observe_session(facts);
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
/// admitted under, never reconstructed from the record, and the receipt
/// reports the stored record whenever this operation identity already holds
/// one so the handler performs its content comparison against what was
/// actually persisted.
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

fn bridge_failure(error: &BridgeError) -> HostEventAdmissionFailure {
    match error {
        BridgeError::StaleAuthority | BridgeError::ExternalAttachReconciliationRequired => {
            HostEventAdmissionFailure::Fenced
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
    /// Effect decisions this admission already committed, keyed by their exact
    /// operation identity. The stored record is what a `Duplicate` from the
    /// route's own ORS replay returns, so the handler compares the presented
    /// request against the record that was actually persisted rather than
    /// against a recomputed one.
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
                if matches!(disposition, EventDisposition::Conflict) {
                    // The stored digest is deliberately not exposed to a
                    // conflicting presenter; the caller reconciles by
                    // replaying its original bytes under the same identity.
                    return Err(HostEventAdmissionError::conflict(String::new()));
                }
                if !matches!(
                    phase,
                    AckPhase::Durable | AckPhase::Normalized | AckPhase::Applied
                ) {
                    return Err(HostEventAdmissionError::of(
                        HostEventAdmissionFailure::Unavailable,
                    ));
                }
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
                    // The retained event carries no decision yet: the decision
                    // is committed under its own identity by `commit_decision`
                    // once the Governor has evaluated it. A decision this
                    // admission already committed for this exact operation is
                    // returned here so a retry after a lost response reconciles
                    // the original decision instead of evaluating a second one.
                    replayed_decision: self.committed_decisions.get(&submission.event_id).cloned(),
                };
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
        if fence.nonce() != record.fence_id || fence.generation().get() != record.bridge_generation
        {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Fenced,
            ));
        }
        let stream_id = format!("{OPENCODE_DECISION_OWNER}.decisions");
        let event_id = record.operation_id.clone();
        if let Some(stored) = self.committed_decisions.get(&event_id) {
            // This exact operation identity already holds a decision. The
            // handler compares the presented record against this stored one by
            // content, so a changed effect, scope, fence, generation or policy
            // revision under one identity is refused without a second policy
            // evaluation and without a second durable write.
            return Ok(decision_receipt(
                stream_id,
                event_id,
                epoch,
                &fence,
                Some(stored.clone()),
            ));
        }
        let generation = ResourceGeneration::new(record.bridge_generation)
            .map_err(|_| HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable))?;
        let envelope = EventEnvelope {
            stream_id: stream_id.clone(),
            producer_id: HOST_EVENTS_DECISION_PRODUCER_ID.to_owned(),
            producer_generation: generation,
            authority_epoch: epoch.clone(),
            event_id: event_id.clone(),
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
        if matches!(disposition, EventDisposition::Conflict) {
            // The same decision identity already holds different content. The
            // stored record is deliberately not disclosed to a conflicting
            // presenter; reconciliation replays the presenter's own original
            // content under the same identity.
            return Err(HostEventAdmissionError::conflict(String::new()));
        }
        if matches!(disposition, EventDisposition::Duplicate) {
            // The route proves this exact content is already durable, but the
            // record it holds is not readable here. Refuse rather than
            // re-evaluate: an unreconcilable duplicate must not become a second
            // decision.
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Unavailable,
            ));
        }
        if !matches!(
            phase,
            AckPhase::Durable | AckPhase::Normalized | AckPhase::Applied
        ) {
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Unavailable,
            ));
        }
        self.committed_decisions
            .insert(event_id.clone(), record.clone());
        Ok(decision_receipt(
            stream_id,
            event_id,
            epoch,
            &fence,
            Some(record.clone()),
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
fn host_events_startup(
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
