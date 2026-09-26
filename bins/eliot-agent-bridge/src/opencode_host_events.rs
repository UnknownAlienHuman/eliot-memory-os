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

use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_agent_bridge_core::{
    AckPhase, BridgeError, CoverageGap, EventDisposition, EventForwardStatus, GapDisposition,
};
use eliot_agent_opencode::{
    CredentialResolver, HOST_EVENTS_PAYLOAD_TYPE, HostEventAdmission, HostEventAdmissionError,
    HostEventAdmissionFailure, HostEventAdmissionReceipt, HostEventDelivery, HostEventGap,
    HostEventKind, HostEventPorts, HostEventSubmission, IntroductionStore, UnconfiguredActionGate,
};
use eliot_contracts::{ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use eliot_process::{FencingToken, Generation, SecretRef};
use eliot_protocol::{DeliveryClass, EventEnvelope, EventPayload, ProtocolPayload};
use eliot_user_broker_core::{OpenCodeBridgeIntroduction, OpenCodeSessionFacts};
use secrecy::SecretString;
use thiserror::Error;

use crate::BridgeRunner;

/// Named gap: Governor/authority `ActionGate` evaluation wiring (issue
/// #2898, step 9). Until a Governor-owned evaluation implements the port,
/// the composition serves [`UnconfiguredActionGate`], which fails every
/// gate closed to a durable-observation-only `recorded` response. Policy
/// is never decided inside the HTTP handler and `recorded` is never
/// promoted to `allow`.
pub const OPENCODE_ACTION_GATE_GAP: &str = "OPENCODE_ACTION_GATE_EVALUATION";

/// Current-introduction holder for the bridge process.
///
/// The User Broker mints introductions; the bridge composition installs
/// the current one here with [`BridgeIntroductionStore::install`], retires
/// rotated entries with [`BridgeIntroductionStore::revoke`], and refreshes
/// live session facts with [`BridgeIntroductionStore::observe_session`].
/// Rotation, listener death, bridge restart, logout, and revocation
/// invalidate the old introduction here before another request is
/// admitted.
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
    /// caller revokes the replaced introduction first when rotation must
    /// invalidate it before another request.
    pub fn install(&mut self, introduction: OpenCodeBridgeIntroduction) {
        self.current = Some(introduction);
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
}

impl<'runner> BridgeHostEventAdmission<'runner> {
    /// Borrows the live runner for same-thread admission.
    pub fn new(runner: &'runner mut BridgeRunner) -> Self {
        Self { runner }
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
                Ok(HostEventAdmissionReceipt {
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
                })
            }
            EventForwardStatus::BestEffortForwarded
            | EventForwardStatus::BestEffortGapSignalled { .. } => Err(
                HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable),
            ),
        }
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

/// Assembles the four ingress ports over the live bridge composition.
///
/// The admission port borrows the runner on the bridge thread; the gate
/// is the explicit fail-closed [`UnconfiguredActionGate`] until the
/// Governor-owned evaluation named by [`OPENCODE_ACTION_GATE_GAP`] is
/// wired; introductions and credentials come from the owner's live store
/// and secret boundary.
pub fn assemble_ports<F>(
    runner: &mut BridgeRunner,
    store: BridgeIntroductionStore,
    resolve_credential: F,
) -> HostEventPorts<
    BridgeHostEventAdmission<'_>,
    UnconfiguredActionGate,
    BridgeIntroductionStore,
    FnCredentialResolver<F>,
>
where
    F: Fn(&SecretRef) -> Option<SecretString> + Send,
{
    HostEventPorts {
        admission: BridgeHostEventAdmission::new(runner),
        gate: UnconfiguredActionGate,
        introductions: store,
        credentials: FnCredentialResolver::new(resolve_credential),
    }
}
