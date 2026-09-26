//! P-04 admitted host-request routing (Waves C + D).
//!
//! Mechanical Kernel admission, durability, and lifecycle handling for one
//! versioned [`HostRequestEnvelope`](eliot_protocol::HostRequestEnvelope)
//! presented by the currently authenticated agent-bridge connection. This
//! module consumes Writer-A's protocol envelopes, admission gate
//! (`KernelService::admit_host_request` / `reconcile_host_request_admission`),
//! and ORS host-request record transitions; it redefines none of them.
//!
//! Authority rules enforced here:
//!
//! - One host request is accepted only from a currently retained bridge
//!   connection with a live accepted transport. Unknown connections fail
//!   closed; a reconnected bridge generation never inherits the previous
//!   connection's Session, capabilities, or pending tickets.
//! - The Kernel builds the bridge process binding itself from the retained
//!   admission descriptor and the retained transport admission receipt. A
//!   caller-supplied binding is never accepted as authority.
//! - Activation consumes the exact retained typed resolution result without
//!   rerunning semantic resolution. Only the Writer-A `validate_resolution`
//!   gate decides whether the result satisfies the envelope; this module maps
//!   its typed outcome to transport errors without interpreting dispositions.
//! - This module creates no transport Session for any kind, grants no
//!   capability, completes no task, mints no canonical truth, and never
//!   produces `VERIFIED_COMPLETE`. It returns admission receipts and durable
//!   ORS records only. Semantic Sessions are created exactly once by the
//!   bridge activation path, and only for a `Resolved` disposition.
//! - Payloads travel by digest only and are never parsed here; capability
//!   membership is enforced by the admission gate, never interpreted.
//! - The one exception is the closed Watchdog intent route
//!   (`WATCHDOG_INTENT_SUBMIT_OPERATION`): it decodes its own typed
//!   `WatchdogSpoolIntentBatchPayload` because the Watchdog's original
//!   restricted record must be *retained verbatim* for forensic linkage, not
//!   reduced to a digest. That is still typed decoding of a named contract, and
//!   it is a separate closed entry rather than a relaxation of the envelope
//!   rule: a Watchdog intent is a parentless observation submission, so it can
//!   neither ride nor widen the host-request envelope. Admitting it records a
//!   durable *pending intent projection* under a derived reconciliation key and
//!   never performs the canonical Problem/Incident transition, which stays the
//!   Governor's.
//! - Raw `Frame` cancellation is never handled here. Cancellation arrives only
//!   as a typed `Cancellation` envelope that stages its own durable record
//!   and advances its exact parent operation.
//! - Persist before acknowledgement: the `Requested` ORS record is staged
//!   before the admission receipt is returned. An exact replay returns the
//!   durable record unchanged; a changed binding under the same identity
//!   fails as an identity conflict.
//!
//! Transport error mapping is mechanical: shape, digest, fence, descriptor,
//! service-gate, and storage failures fail closed as `SessionFenced`; a
//! changed binding under a known identity is `IdentityConflict`; an unknown
//! ticket, parent, or operation is `UnknownRequest`; an elapsed absolute
//! deadline is `Timeout`. No error prose drives routing.

use super::{
    Frame, FrameKind, GovernanceProfile, KernelComposition, KernelFrameAction, MessageType,
    ProtocolPayload, Session, TransportError, activation_deadline_expired, sha256_json,
    status_frame, unix_ms,
};
use eliot_ipc::PeerIdentity;
use eliot_kernel_service::{AgentBridgeAdmissionDescriptor, KernelServiceState};
use eliot_ors::{
    CONTRACT_VERSION as ORS_CONTRACT_VERSION, HostRequestKind as OrsHostRequestKind,
    HostRequestRecord, HostRequestState, OpaqueLabel, OperationIdentity, OrsError,
    RedbRecoveryStore,
};
use eliot_protocol::{
    AGENT_BRIDGE_PROCESS_BINDING_WIRE_ID, AgentActivationResolutionResult,
    AgentBridgePeerAdmissionReceipt, AgentBridgeProcessBinding, DeliveryClass, EventEnvelope,
    HOST_REQUEST_INVOKE_READ_WIRE_ID, HOST_REQUEST_RESULT_BODY_WIRE_ID,
    HostRequestAdmissionReceipt, HostRequestEnvelope, HostRequestInvokeReadPayload,
    HostRequestKind, HostRequestResultBody, LocalReadAttempt, WatchdogIntentKind,
    WatchdogSpoolIntentBatchPayload, WatchdogSpoolIntentSubmission, host_request_operation_id,
};
use eliot_store_api::{CampaignLearningStateViewPublication, EVIDENCE_PACK_MAX_RECORDS, ScopeId};

mod daemon_claim_queue;

use self::daemon_claim_queue::{campaign_packet_admission, check_task_controller_admission};

/// Prefix of the deterministic opaque operation handle derived by
/// [`host_request_operation_id`]. A parent operation reference carries the
/// parent envelope digest after this prefix; the digest is re-validated as
/// lowercase SHA-256 before any store lookup, so a malformed reference is an
/// unknown operation rather than a fence failure.
const HOST_REQUEST_OPERATION_ID_PREFIX: &str = "hostreq:";

/// Typed frame operations carrying one [`HostRequestEnvelope`] through the
/// closed frame gateway.
///
/// Names follow the `agent_activation_*` daemon-operation style. The payload
/// carries the exact envelope under `envelope` (plus the exact admission
/// receipt under `receipt` for rehydrate, or the typed resolve query under
/// `query` for resolve); the operation string only selects which closed entry — admit, cancel, reconcile, rehydrate, or resolve — consumes it.
/// There is no generic JSON command dispatch: the envelope is decoded as the
/// typed [`HostRequestEnvelope`] (with its canonical digest check) and the
/// envelope kind is re-enforced by the callee.
pub(crate) const AGENT_HOST_REQUEST_SUBMIT_OPERATION: &str = "agent_host_request_submit";
pub(crate) const AGENT_HOST_REQUEST_CANCEL_OPERATION: &str = "agent_host_request_cancel";
pub(crate) const AGENT_HOST_REQUEST_RECONCILE_OPERATION: &str = "agent_host_request_reconcile";
pub(crate) const AGENT_HOST_REQUEST_REHYDRATE_OPERATION: &str = "agent_host_request_rehydrate";
/// Closed lookup-only resolve entry (issue #2571: cross-restart replay
/// without double execution).
///
/// Carries the exact current-transport resolve envelope (always the
/// observation-only `Status` kind) plus the typed resolve query under
/// `query` (`logical-key` or `operation-handle` form). The entry never
/// stages a row, issues a receipt, advances state, or runs provider work: it
/// answers the durable record in the existing rehydrated shape on a hit, or
/// an explicit `accepted:false` resolve value (`absent` or `conflict`)
/// otherwise. A `Status` envelope without a parent is accepted on this entry
/// only; every other entry keeps the exact-parent rule.
pub(crate) const AGENT_HOST_REQUEST_RESOLVE_OPERATION: &str = "agent_host_request_resolve";
/// Closed invoke-read entry for local reads (Implements #18: local read result).
///
/// Carries the exact envelope plus the exact canonical tool bytes it admits,
/// so tool linkage (capability + payload digest) is re-checked before any
/// read and the exact bounded result with its revision can be served back
/// from the durable record without re-dispatch. The envelope stays
/// digest-only in spirit; the tool bytes only prove the presented operation
/// is the admitted one.
pub(crate) const AGENT_HOST_REQUEST_INVOKE_READ_OPERATION: &str = "agent_host_request_invoke_read";

/// Closed agent-bridge event-delivery entries (Implements #2561, I7.2/I7.23).
///
/// The four forwarding methods ride the same admitted front-door transport
/// through this closed gateway — no second transport, no generic command
/// dispatch. Each payload carries its typed envelope under `envelope` (the
/// durable/control [`EventEnvelope`] for forward, the digest-bound hook JSON
/// for hook, the coverage gap JSON for gap, the reconcile scope for
/// reconcile); the operation string only selects which closed entry consumes
/// it. Events are never submitted as host requests, and host-request
/// submit/cancel/reconcile entries never read the bridge-event tables.
pub(crate) const AGENT_BRIDGE_EVENT_FORWARD_OPERATION: &str = "agent_bridge_event_forward";
/// Closed hook-observation entry: digest-bound RECEIVED observation without a
/// durable phase (the hook signature carries no acknowledgement).
pub(crate) const AGENT_BRIDGE_HOOK_FORWARD_OPERATION: &str = "agent_bridge_hook_forward";
/// Closed coverage-gap entry: persists missing-coverage accounting without
/// moving any cursor.
pub(crate) const AGENT_BRIDGE_EVENT_GAP_OPERATION: &str = "agent_bridge_event_gap";
/// Closed event-ownership/cursor reconciliation entry: reads the bridge-event
/// tables only, never the host-request ledger.
pub(crate) const AGENT_BRIDGE_EVENT_RECONCILE_OPERATION: &str = "agent_bridge_event_reconcile";

/// Bound on queued local-read pairs for the outbound-only eliotd poller.
///
/// Mirrors the bounded activation replay/result ledgers (64): the durable ORS
/// record owns lifecycle state, so eviction only drops daemon-leg queue
/// memory and never fabricates admission.
const MAX_QUEUED_LOCAL_READS: usize = 64;

/// Returns whether the operation string selects the P-04 host-request route.
///
/// The closed agent-bridge event-delivery entries ride this same predicate:
/// they cross the same admitted front-door gateway and the same
/// `dispatch_host_request_frame` entry, which fans out to the event handlers
/// before any host-request envelope decode.
pub(crate) fn is_host_request_operation(operation: &str) -> bool {
    matches!(
        operation,
        AGENT_HOST_REQUEST_SUBMIT_OPERATION
            | AGENT_HOST_REQUEST_CANCEL_OPERATION
            | AGENT_HOST_REQUEST_RECONCILE_OPERATION
            | AGENT_HOST_REQUEST_REHYDRATE_OPERATION
            | AGENT_HOST_REQUEST_RESOLVE_OPERATION
            | AGENT_HOST_REQUEST_INVOKE_READ_OPERATION
            | AGENT_BRIDGE_EVENT_FORWARD_OPERATION
            | AGENT_BRIDGE_HOOK_FORWARD_OPERATION
            | AGENT_BRIDGE_EVENT_GAP_OPERATION
            | AGENT_BRIDGE_EVENT_RECONCILE_OPERATION
    )
}

/// Returns whether the operation string selects the closed agent-bridge
/// event-delivery entries (the #2561 subset of [`is_host_request_operation`]).
pub(crate) fn is_bridge_event_operation(operation: &str) -> bool {
    matches!(
        operation,
        AGENT_BRIDGE_EVENT_FORWARD_OPERATION
            | AGENT_BRIDGE_HOOK_FORWARD_OPERATION
            | AGENT_BRIDGE_EVENT_GAP_OPERATION
            | AGENT_BRIDGE_EVENT_RECONCILE_OPERATION
    )
}

/// Returns whether the operation string selects the fenced Watchdog intent
/// route.
///
/// The intent route is deliberately **not** part of
/// [`is_host_request_operation`]: a Watchdog intent has no parent operation, and
/// every host-request kind that could carry it (`Status` and `Reconciliation`)
/// requires one exact previously admitted parent by contract. Folding it into
/// that predicate would either break the envelope contract or grant the
/// Watchdog a parent operation it does not own. It is a separate closed entry
/// with its own payload, envelope validation, and named mutation, reachable
/// from the front door through [`is_watchdog_intent_operation`].
pub(crate) fn is_watchdog_intent_operation(operation: &str) -> bool {
    operation == WATCHDOG_INTENT_SUBMIT_OPERATION
}

/// Connection-scoped reference to one staged host-request operation.
///
/// The durable ORS record owns lifecycle state; this reference only lets
/// disconnect revocation fence the presenting connection's still-uncertain
/// operations without enumerating the store.
///
/// A queued local-read pair rides this same index so disconnect revocation
/// still fences it without a new per-Kernel field (residual: move to a
/// dedicated `Mutex<LocalReadPendingState>` once the composition root
/// widens to initialize it; see HANDOFF). `local_read_envelope`/`local_read_tool`
/// are `Some` only for admitted `eliot.query` invoke-reads whose selectors
/// validated; ordinary indexed operations carry `None` and are never served
/// to the daemon poller. `local_read_attempt` is the governed attempt
/// ownership record for the pair: minted at enqueue as unclaimed
/// (`generation == 0`), claimed by fencing generation at poll time, and
/// retired or fenced away on completion, expiry, disconnect, restart, epoch
/// rotation, or revocation. Removal from this index IS invalidation: submit
/// requires a live record, so a dropped pair can never complete again.
#[derive(Clone, Debug)]
pub(crate) struct HostRequestOperationRef {
    pub(crate) operation_id: String,
    pub(crate) request_digest: String,
    pub(crate) local_read_envelope: Option<HostRequestEnvelope>,
    pub(crate) local_read_tool: Option<serde_json::Value>,
    /// Governed attempt ownership for an admitted `eliot.query` pair. This
    /// queue is never used for campaign packets.
    pub(crate) local_read_attempt: LocalReadAttemptState,
    /// Queued observe pair for the daemon observe poller (issue #2565). Set
    /// only for admitted `eliot.observe` invocations whose tool bytes proved
    /// linkage: the exact envelope plus the exact retained tool bytes the
    /// daemon flight claims and decodes. Ordinary indexed operations and
    /// local-read pairs carry `None` and are never served to the observe
    /// poller; observe pairs are never served to the local-read poller.
    /// Tool bytes live in queue memory only — never persisted, never logged —
    /// while the durable ORS record owns lifecycle state.
    pub(crate) observe_envelope: Option<HostRequestEnvelope>,
    pub(crate) observe_tool: Option<serde_json::Value>,
    /// Unique in-flight admission reservation. Reservations count against the
    /// bounded Observe queue, but carry no executable payload and cannot be
    /// claimed until the durable admission handoff completes.
    pub(crate) observe_reservation: Option<u64>,
    /// Governed attempt ownership for the queued observe pair. Reuses the
    /// shared [`LocalReadAttemptState`] vehicle (generation, boot-unique
    /// identity, owner session); the wire capability disambiguates through
    /// its admitted `facet_method` (`eliot.observe`). Never time-expires;
    /// only explicit retire/fence transitions invalidate it. Observe is a
    /// mutating path, so — unlike the read-only local-read leg — completion
    /// additionally advances the durable ORS phase (`Routed` on daemon
    /// defer, `ResultReceived` on submit) before the queue pair retires.
    pub(crate) observe_attempt: LocalReadAttemptState,
    /// Campaign packet pair queued for the packet poller. It has an
    /// independent queue slot and attempt ledger and can never be claimed by
    /// the evidence-query poller.
    pub(crate) campaign_packet_envelope: Option<HostRequestEnvelope>,
    pub(crate) campaign_packet_tool: Option<serde_json::Value>,
    pub(crate) campaign_packet_attempt: LocalReadAttemptState,
    /// Task Controller invocation pair queued for the authenticated daemon
    /// poller. It is kept separate from the local-read marker so a task
    /// invocation can never be interpreted as an evidence query.
    pub(crate) task_controller_envelope: Option<HostRequestEnvelope>,
    pub(crate) task_controller_tool: Option<serde_json::Value>,
    pub(crate) task_controller_attempt: LocalReadAttemptState,
}

/// Governed attempt ownership record for one queued local-read pair.
///
/// Mirrors the T12-10 model-attempt shape (`JobLease` + bound receipt):
/// exactly one current fencing generation per operation, a boot-unique
/// attempt identity, and an owner session binding. `generation == 0` means
/// never claimed; otherwise the record names the live attempt and its owning
/// daemon session. Only the live `(attempt_id, generation, owner)` triple may
/// complete the operation.
///
/// `enqueue_salt` makes the attempt identity unique per queue lifecycle: a
/// re-enqueued pair (after retire or fence) restarts at generation 1 but with
/// a fresh salt, so a capability minted for the previous lifecycle can never
/// match the new record — even in the same boot with the same owner session.
#[derive(Clone, Debug, Default)]
pub(crate) struct LocalReadAttemptState {
    pub(crate) attempt_id: String,
    pub(crate) generation: u64,
    pub(crate) enqueue_salt: u64,
    pub(crate) owner_connection_id: String,
    pub(crate) owner_launch_nonce: String,
    pub(crate) owner_session_epoch: u64,
}

impl LocalReadAttemptState {
    /// Returns whether this record names a live (claimed, unretired) attempt.
    pub(crate) fn is_live(&self) -> bool {
        self.generation != 0
    }

    /// Returns whether the presenting daemon session owns the live attempt.
    pub(crate) fn is_owned_by(&self, session: &Session) -> bool {
        self.is_live()
            && self.owner_connection_id == session.connection_id
            && self.owner_launch_nonce == session.launch_nonce
            && self.owner_session_epoch == session.session_epoch
    }
}

/// Noncanonical stale-attempt observation: a late, duplicate, mismatched, or
/// revoked submission that must never reach a waiting caller.
///
/// The observation is retained for forensics (returned to the submitter as an
/// audit receipt and projected as the stale wire outcome); the durable ORS
/// record is untouched, so the waiter observes no stale result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StaleLocalReadObservation {
    pub(crate) operation_id: String,
    pub(crate) request_digest: String,
    pub(crate) presented_attempt_id: Option<String>,
    pub(crate) presented_generation: Option<u64>,
    pub(crate) current_generation: Option<u64>,
    pub(crate) reason: StaleLocalReadReason,
}

/// Closed reason codes for a stale local-read submission. Codes are control
/// values, never human prose: no error text drives routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StaleLocalReadReason {
    /// No live claim record: never claimed, already retired, or fenced away
    /// by disconnect, restart, epoch rotation, or revocation.
    Unclaimed,
    /// A live record exists but the presented identity/generation is not
    /// current: lease replacement, reassignment, or a duplicated attempt.
    Superseded,
    /// Identity and generation match but the presenting session does not own
    /// the attempt: the owner reconnected or was replaced without revocation.
    OwnerMismatch,
}

impl StaleLocalReadReason {
    /// Stable wire code for the stale daemon outcome.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unclaimed => "unclaimed",
            Self::Superseded => "superseded",
            Self::OwnerMismatch => "owner-mismatch",
        }
    }
}

/// Disposition of one daemon-produced local-read result submission.
///
/// `Persisted` is the single completion for the current fencing generation;
/// `StaleAttempt` is the quarantined noncanonical observation. There is no
/// third outcome: exactly one completion per current generation.
#[derive(Clone, Debug)]
pub(crate) enum LocalReadSubmitDisposition {
    Persisted(Box<HostRequestRecord>),
    StaleAttempt(StaleLocalReadObservation),
}

#[derive(Clone, Copy)]
enum DaemonReadQueue {
    Query,
    CampaignPacket,
}

impl KernelComposition {
    /// Admits one versioned host-request envelope for routing.
    ///
    /// Runs the mechanical transport, descriptor, service-gate, deadline, and
    /// durability checks in order, stages the `Requested` ORS record before
    /// acknowledging, advances it to `Admitted`, performs the kind-specific
    /// parent step for `Cancellation`/`Status`/`Reconciliation`, and returns
    /// the Writer-A admission receipt with the durable record. An exact
    /// replay returns the existing record without advancing it again.
    pub fn admit_host_request_envelope(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<(HostRequestAdmissionReceipt, HostRequestRecord), TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        self.admit_host_request_envelope_under_transition(envelope)
    }

    fn admit_host_request_envelope_under_transition(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<(HostRequestAdmissionReceipt, HostRequestRecord), TransportError> {
        envelope
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = unix_ms();
        let expired = activation_deadline_expired(now, envelope.identity.deadline_unix_ms);

        let (descriptor, receipt) = self.host_request_connection_gate_under_transition(envelope)?;
        self.host_request_service_gate(&descriptor, envelope)?;
        let binding = bridge_process_binding(&descriptor, &receipt, &envelope.connection_id)?;

        // Activation consumes the exact retained typed result. The resolver is
        // never invoked here; a missing ticket or result is an unknown
        // operation, a digest or fence mismatch is an identity conflict, and a
        // non-resolved disposition fails closed without a Session.
        let resolution: Option<AgentActivationResolutionResult> =
            if envelope.kind == HostRequestKind::Activation {
                Some(self.host_request_activation_resolution_under_transition(envelope)?)
            } else {
                None
            };
        let requested = requested_host_request_record(envelope)?;
        let operation_id = OperationIdentity::new(host_request_operation_id(envelope))
            .map_err(|_| TransportError::SessionFenced)?;
        let existing = self
            .generation_gateway
            .ors
            .load_host_request(&operation_id, &envelope.envelope_sha256)
            .map_err(|_| TransportError::SessionFenced)?;
        // Exact replay of an admitted or terminal operation remains an
        // observation path. A fresh or still-Requested Invocation can still
        // grant authority, so reject it before service admission and before
        // any durable Requested row is written. Expired presentations are
        // staged below without Material admission and closed in the same CAS
        // path as the original late-delivery contract.
        let needs_material_authority = matches!(
            envelope.kind,
            HostRequestKind::Activation | HostRequestKind::Invocation
        ) && existing
            .as_ref()
            .is_none_or(|record| !record.state.is_terminal());
        if !expired && needs_material_authority {
            self.admit_material_authority_for_fence(
                GovernanceProfile::full(),
                &envelope.state_fence,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        }

        let admission_receipt = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            service
                .admit_host_request(envelope, &descriptor, &binding, resolution.as_ref())
                .map_err(|_| TransportError::SessionFenced)?
        };
        let stored = self
            .stage_host_request_with_logical_claim(&requested)
            .map_err(|error| match error {
                OrsError::HostRequestIdentityConflict { .. } => TransportError::IdentityConflict,
                _ => TransportError::SessionFenced,
            })?;

        // An elapsed absolute deadline is staged honestly, then closed as
        // expired instead of admitted. The caller observes a timeout; the
        // durable record preserves the late presentation. Operations that may
        // already have produced effects stay under their owner's
        // reconciliation rules because the transition table forbids expiring
        // them blindly.
        if expired {
            if !stored.state.is_terminal() {
                match self.generation_gateway.ors.advance_host_request(
                    &operation_id,
                    &envelope.envelope_sha256,
                    HostRequestState::Expired,
                    None,
                ) {
                    Ok(_) | Err(OrsError::InvalidTransition) => {}
                    Err(_) => return Err(TransportError::SessionFenced),
                }
            }
            self.note_host_request_operation_under_transition(envelope)?;
            return Err(TransportError::Timeout);
        }

        let admitted = if stored.state == HostRequestState::Requested {
            self.generation_gateway
                .ors
                .advance_host_request(
                    &operation_id,
                    &envelope.envelope_sha256,
                    HostRequestState::Admitted,
                    None,
                )
                .map_err(|_| TransportError::SessionFenced)?
                .ok_or(TransportError::SessionFenced)?
        } else {
            // Exact replay of an already staged operation: return the durable
            // record unchanged without advancing it again.
            stored
        };

        match envelope.kind {
            HostRequestKind::Cancellation => {
                self.advance_host_request_parent(envelope, &descriptor)?;
            }
            HostRequestKind::Status => {
                self.require_known_host_request_parent(envelope, &descriptor)?;
            }
            HostRequestKind::Reconciliation => {
                self.reconcile_host_request_parent(envelope, &descriptor)?;
            }
            HostRequestKind::Activation | HostRequestKind::Invocation => {}
        }

        self.note_host_request_operation_under_transition(envelope)?;
        Ok((admission_receipt, admitted))
    }

    /// Stages one `Requested` host-request row, claiming its logical key when
    /// it carries one (issue #2571: the production logical-key writer).
    ///
    /// Records with a canonical logical key (session-bound `Invocation` or
    /// `Cancellation`) go through the owner's atomic resolve-or-stage entry,
    /// so the key claim and the operation row commit in one write
    /// transaction: the first stage wins, an exact replay returns the winner
    /// unchanged, and a changed commitment under a known key fails as an
    /// identity conflict. Records without a key (every other kind, or a
    /// missing session) keep the legacy stage path unchanged. A winner
    /// reached under a different operation identity fails closed through the
    /// advance join in the admit path, which only ever advances the
    /// presented identity.
    fn stage_host_request_with_logical_claim(
        &self,
        requested: &HostRequestRecord,
    ) -> Result<HostRequestRecord, OrsError> {
        let keyed = RedbRecoveryStore::host_request_logical_key_for_record(requested)?.is_some();
        if keyed {
            self.generation_gateway
                .ors
                .resolve_or_stage_host_request(requested)
        } else {
            self.generation_gateway.ors.stage_host_request(requested)
        }
    }

    /// Admits one Watchdog spool intent batch through the fenced named Kernel
    /// intent mutation, exactly once per retained spool record.
    ///
    /// This is the Kernel half of the I8.1 reconciliation path. It records a
    /// **pending intent projection** and nothing else: each submitted
    /// `problem_intent` / `incident_intent` becomes one durable ORS
    /// `Reconciliation` host-request record whose durable identity is the
    /// derived reconciliation key, so the first submission wins and every later
    /// submission of the same spool record replays to that same record instead
    /// of creating a second projection. Changed bytes under the same key are an
    /// identity conflict, not a second intent.
    ///
    /// The distinction the issue requires is preserved by construction: the
    /// Kernel stops at the durable `Admitted` state and never writes a result
    /// body, so the projection stays a *watchdog intent awaiting a Governor
    /// decision*. Advancing it past `Admitted` is the Governor's leg, not this
    /// entry's. The canonical Problem/Incident transition, the Current Epistemic
    /// Position, task state, and every other semantic decision stay owned by the
    /// Governor consuming this record. The Watchdog gains no canonical,
    /// ORS-authoring, or `HostStateJournal` authority from this entry: it submits
    /// an observation through a named Kernel mutation, exactly as I1.8 requires.
    ///
    /// The original Watchdog record travels verbatim inside each submission and
    /// is retained by the Watchdog spool, so the Kernel projection and the
    /// Governor's later decision both stay forensically linked to it.
    ///
    /// The entry and its projection stay inside this crate on purpose: the
    /// Watchdog reaches the mutation only through the admitted frame front door
    /// in [`Self::dispatch_watchdog_intent_frame`], and the projections it
    /// returns are rendered into that frame's typed answer, so no caller outside
    /// the Kernel can name or hold one.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::SessionFenced`] when the payload, envelope
    /// joins, fence, session, or service state are unusable, and
    /// [`TransportError::IdentityConflict`] when a submission replays under a
    /// key already bound to different bytes.
    pub(crate) fn admit_watchdog_intent_batch(
        &self,
        session: &Session,
        payload: &WatchdogSpoolIntentBatchPayload,
    ) -> Result<Vec<WatchdogIntentProjection>, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        payload
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = unix_ms();
        if self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?
            != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        if !session.accepts(&session.authority_epoch, session.session_epoch) {
            return Err(TransportError::SessionFenced);
        }
        // The submission must ride the *current* supervision lease the Kernel
        // itself retains, not merely a live transport session: a front-door
        // session proves who is connected, while only the retained supervision
        // lease proves which Watchdog generation and epoch are currently
        // admitted. A stale generation, a superseded epoch, or a lease the
        // Kernel does not hold therefore fences here and can never stage a
        // record.
        let admitted_generation = self.admitted_watchdog_generation(payload)?;
        // The mechanical envelope joins run before any durable write, so a
        // forged or stale window never stages a record.
        validate_watchdog_spool_batch_envelope(
            payload.predecessor_sequence,
            payload.first_sequence,
            payload.last_sequence,
            payload.high_water_sequence,
            payload.watchdog_generation,
            payload.watchdog_epoch,
            &payload.installation_id,
            &payload.sink_id,
            &payload.route,
            admitted_generation,
            payload.watchdog_epoch,
            &session.connection_id,
            &session.connection_id,
            payload.created_at_ms,
            payload.expires_at_ms,
            now,
            false,
            payload.intents.len(),
            payload.batch_digest.len() as u64,
        )?;
        let mut projections = Vec::with_capacity(payload.intents.len());
        for intent in &payload.intents {
            projections.push(self.stage_watchdog_intent_projection(payload, intent)?);
        }
        Ok(projections)
    }

    /// Resolves the Watchdog generation the Kernel currently admits, from the
    /// retained supervision lease the batch names.
    ///
    /// The submitted `watchdog_generation` and `watchdog_epoch` must equal the
    /// activation generation and Watchdog epoch of the durable lease record the
    /// Kernel holds, and the named installation must match it exactly. A
    /// missing authority, an unknown lease, a non-current record, a different
    /// installation, or any divergence fences closed before a durable write, so
    /// a stale Watchdog generation can never stage a pending intent.
    fn admitted_watchdog_generation(
        &self,
        payload: &WatchdogSpoolIntentBatchPayload,
    ) -> Result<u64, TransportError> {
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let snapshot = authority
            .current_snapshot(&payload.supervision_lease_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        let binding = &snapshot.record.binding;
        if binding.installation_id.as_str() != payload.installation_id
            || binding.watchdog_epoch.value() != payload.watchdog_epoch
            || binding.activation_generation.value() != payload.watchdog_generation
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(payload.watchdog_generation)
    }

    /// Stages the durable pending-intent projection for one submitted intent.
    ///
    /// The durable identity is the derived reconciliation key, so
    /// `stage_host_request` first-writer-wins semantics give exactly-once
    /// admission per spool record: an exact replay returns the stored record
    /// unchanged, and changed bytes under the same key fail as
    /// `HostRequestIdentityConflict`.
    fn stage_watchdog_intent_projection(
        &self,
        payload: &WatchdogSpoolIntentBatchPayload,
        intent: &WatchdogSpoolIntentSubmission,
    ) -> Result<WatchdogIntentProjection, TransportError> {
        let operation_id = OperationIdentity::new(format!(
            "{WATCHDOG_INTENT_OPERATION_ID_PREFIX}{}",
            intent.idempotency_key
        ))
        .map_err(|_| TransportError::SessionFenced)?;
        let record = watchdog_intent_projection_record(payload, intent, &operation_id)?;
        let stored = self
            .generation_gateway
            .ors
            .stage_host_request(&record)
            .map_err(|error| match error {
                OrsError::HostRequestIdentityConflict { .. } => TransportError::IdentityConflict,
                _ => TransportError::SessionFenced,
            })?;
        // A still-`Requested` row is one this call must advance; an
        // already-advanced row is an exact replay, which is reported honestly
        // instead of being re-advanced. This is the Kernel-side half of
        // exactly-once: the durable record exists once per derived key, and
        // the answer tells the Watchdog which case it observed.
        let admitted_now = stored.state == HostRequestState::Requested;
        let admitted = if admitted_now {
            self.generation_gateway
                .ors
                .advance_host_request(
                    &operation_id,
                    &record.request_digest,
                    HostRequestState::Admitted,
                    None,
                )
                .map_err(|error| match error {
                    OrsError::HostRequestIdentityConflict { .. } => {
                        TransportError::IdentityConflict
                    }
                    _ => TransportError::SessionFenced,
                })?
                .ok_or(TransportError::SessionFenced)?
        } else {
            stored
        };
        // `stage_host_request` already compared the complete binding
        // (`same_binding`, which excludes only ORS-owned state/result/order) and
        // returned `HostRequestIdentityConflict` on any divergence, so reaching
        // here proves the stored row is this submission's own record.
        //
        // A pending intent projection carries no result body: the canonical
        // Problem/Incident decision is the Governor's, and this Kernel entry
        // must never imply one by writing a result for a record it only
        // admitted.
        if admitted.result_digest.is_some() {
            return Err(TransportError::SessionFenced);
        }
        Ok(WatchdogIntentProjection {
            sequence: intent.sequence,
            idempotency_key: intent.idempotency_key.clone(),
            intent_kind: intent.intent_kind,
            record_digest: intent.record_digest.clone(),
            payload_digest: intent.payload_digest.clone(),
            operation_id: admitted.operation_id.as_str().to_owned(),
            state: admitted.state,
            admitted_now,
        })
    }

    /// Admits one typed cancellation envelope for its exact parent operation.
    ///
    /// Only the closed `Cancellation` kind is accepted here; raw transport
    /// cancellation frames never reach this entry.
    pub fn cancel_host_request(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<(HostRequestAdmissionReceipt, HostRequestRecord), TransportError> {
        if envelope.kind != HostRequestKind::Cancellation {
            return Err(TransportError::SessionFenced);
        }
        self.admit_host_request_envelope(envelope)
    }

    /// Admits one typed status or reconciliation envelope.
    ///
    /// Both kinds are observation-only at this layer: they stage their own
    /// durable record and reconcile the exact parent without changing
    /// canonical truth, task state, or capabilities.
    pub fn reconcile_host_request(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<(HostRequestAdmissionReceipt, HostRequestRecord), TransportError> {
        if !matches!(
            envelope.kind,
            HostRequestKind::Status | HostRequestKind::Reconciliation
        ) {
            return Err(TransportError::SessionFenced);
        }
        self.admit_host_request_envelope(envelope)
    }

    /// Admits one typed invoke-read envelope with its canonical tool bytes.
    ///
    /// The closed `Invocation` kind is the only kind accepted here. Tool
    /// linkage (capability + payload digest over the presented bytes) is
    /// checked at decode time, and the full admission gate (connection,
    /// descriptor, fence, deadline, durability) runs before anything is read
    /// back, so a changed payload digest or forged descriptor is rejected
    /// before reading. An exact replay of a resulted operation serves the
    /// stored bounded result with its revision without re-dispatch; a live
    /// operation returns its admission receipt honestly.
    ///
    /// No semantic result is produced here: `eliot.query` is dispatched by
    /// the authenticated query read leg, while `eliot.packet` is queued for
    /// the production campaign compiler in `eliotd`. This entry owns
    /// admission, linkage rejection, queueing, and exact readback; the
    /// `KernelHostRequestBinder::invoke_admitted` persist/readback pair owns
    /// the dispatch-then-store leg wherever a Governor is injected.
    pub fn invoke_read_host_request(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
    ) -> Result<(HostRequestAdmissionReceipt, HostRequestRecord), TransportError> {
        if envelope.kind != HostRequestKind::Invocation {
            return Err(TransportError::SessionFenced);
        }
        HostRequestInvokeReadPayload {
            wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
            wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
            envelope: envelope.clone(),
            tool: tool.clone(),
        }
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
        let _transition = self.agent_bridge_transition_read()?;
        let (receipt, record) = self.admit_host_request_envelope_under_transition(envelope)?;
        // Queue each admitted shape in its own Kernel-owned lane. A packet is
        // never handed to the query queue or selector derivation.
        if record.result_digest.is_none() {
            match check_local_read_admission(envelope, tool) {
                Ok(LocalReadAdmission::Query(_)) => {
                    // Queue admission is part of the same authenticated
                    // operation. Never acknowledge a request whose bounded
                    // query queue could not retain it.
                    self.enqueue_local_read_pair_under_transition(envelope, tool)?;
                }
                Ok(LocalReadAdmission::CampaignPacket { .. }) => {
                    self.enqueue_campaign_packet_pair_under_transition(envelope, tool)?;
                }
                Err(_) => {
                    if check_task_controller_admission(envelope, tool).is_ok() {
                        self.enqueue_task_controller_pair_under_transition(envelope, tool)?;
                    } else if check_local_state_admission(envelope, tool).is_ok() {
                        // #2564 I4 state-carrier seam: validated `eliot.state`
                        // pairs attempt the shared local-read carrier for the
                        // outbound-only eliotd poller. The carrier enqueue
                        // gate and the claim gate are query-only today, so the
                        // attempt is refused without side effects (the gate is
                        // the first statement of the enqueue fn, before any
                        // mutation); the serve leg that admits state pairs is
                        // #2565's dispatch lane.
                        let _ = self.enqueue_local_read_pair_under_transition(envelope, tool);
                    }
                }
            }
        }
        // Coherence gate before serving: a resulted record must carry a
        // digest-bound body, otherwise the row is never served as an answer.
        if let (Some(digest), Some(body)) = (&record.result_digest, &record.result_response) {
            HostRequestResultBody {
                wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
                wire_version: HostRequestResultBody::CONTRACT_VERSION,
                operation_id: receipt.operation_id.clone(),
                request_sha256: envelope.envelope_sha256.clone(),
                result_digest: digest.clone(),
                response: body.clone(),
                // Coherence gate only: stored rows predate attempt ownership.
                attempt: None,
            }
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        }
        Ok((receipt, record))
    }

    /// Rehydrates one previously admitted host request after restart or an
    /// unknown delivery without rerunning semantic resolution.
    ///
    /// Proves only that the retained receipt binds the exact envelope and
    /// that the envelope still matches the current descriptor generation and
    /// fence, then returns the durable ORS record under its exact identity.
    /// Stale bridge generations never revive: an envelope bound to a
    /// superseded descriptor or fence fails closed. No receipt is issued, no
    /// state is advanced, no Session is created, and no provider work runs.
    pub fn rehydrate_host_request(
        &self,
        envelope: &HostRequestEnvelope,
        receipt: &HostRequestAdmissionReceipt,
    ) -> Result<HostRequestRecord, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        envelope
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        receipt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            service
                .reconcile_host_request_admission(receipt, envelope)
                .map_err(|_| TransportError::SessionFenced)?;
            if !matches!(
                service.state(),
                KernelServiceState::Ready | KernelServiceState::Degraded
            ) {
                return Err(TransportError::SessionFenced);
            }
        }
        {
            let profile = self
                .agent_bridge_profile
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            if envelope.descriptor_sha256 != profile.admission.descriptor_sha256
                || envelope.state_fence != profile.admission.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
        }
        let expected = requested_host_request_record(envelope)?;
        let operation_id = OperationIdentity::new(host_request_operation_id(envelope))
            .map_err(|_| TransportError::SessionFenced)?;
        let stored = self
            .generation_gateway
            .ors
            .load_host_request(&operation_id, &envelope.envelope_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if !stored.same_binding(&expected) {
            return Err(TransportError::IdentityConflict);
        }
        Ok(stored)
    }

    /// Resolves one logical host request or one exact operation handle
    /// without staging or dispatch (issue #2571).
    ///
    /// Lookup-only recovery read for a restarted Bridge: the presenting
    /// resolve envelope is current transport (connection, session, fence,
    /// descriptor), never the recovered operation's authority, so no receipt
    /// is issued, no state is advanced, and no provider work runs. A `Status`
    /// envelope without a parent is accepted on this entry only; the admit
    /// path keeps its exact-parent rule untouched.
    ///
    /// The `logical-key` form carries the presented key plus the occurrence,
    /// capability, and payload selectors: a store miss answers authoritatively
    /// absent, a hit whose winner recomputes to the presented key and matches
    /// every selector answers the durable record in the rehydrated shape with
    /// the key echo, and a hit under a changed commitment answers conflict.
    /// A divergent link or any storage failure fails closed as
    /// `SessionFenced` — never absence, never a fresh-operation permit. The
    /// `operation-handle` form loads the exact handle and checks session
    /// continuity and current generation rights; denial answers exactly like
    /// absence so no foreign task or payload is disclosed.
    fn resolve_host_request_by_logical_key(
        &self,
        envelope: &HostRequestEnvelope,
        query: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        if envelope.kind != HostRequestKind::Status {
            return Err(TransportError::SessionFenced);
        }
        let (descriptor, _) = self.host_request_connection_gate_under_transition(envelope)?;
        self.host_request_service_gate(&descriptor, envelope)?;
        {
            let profile = self
                .agent_bridge_profile
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            if envelope.descriptor_sha256 != profile.admission.descriptor_sha256
                || envelope.state_fence != profile.admission.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
        }
        let session = envelope
            .identity
            .session_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let object = query.as_object().ok_or(TransportError::SessionFenced)?;
        match object.get("form").and_then(serde_json::Value::as_str) {
            Some("logical-key") => {
                if envelope.identity.parent_operation_id.is_some() {
                    return Err(TransportError::SessionFenced);
                }
                let key = resolve_digest_field(object, "logical_key")?;
                let occurrence = resolve_text_field(object, "occurrence")?;
                let capability = resolve_text_field(object, "capability")?;
                let payload = resolve_digest_field(object, "payload_digest")?;
                let stored = self
                    .generation_gateway
                    .ors
                    .load_host_request_by_logical_key(&key)
                    .map_err(|_| TransportError::SessionFenced)?;
                let Some(record) = stored else {
                    return Ok(host_request_resolve_unresolved_response(
                        "absent",
                        Some(&key),
                        None,
                    ));
                };
                let recomputed = RedbRecoveryStore::host_request_logical_key_for_record(&record)
                    .map_err(|_| TransportError::SessionFenced)?
                    .ok_or(TransportError::SessionFenced)?;
                if recomputed != key {
                    return Err(TransportError::SessionFenced);
                }
                if record.request_id.as_str() != occurrence
                    || record.capability_ref.as_str() != capability
                    || record.payload_digest != payload
                    || record.session_ref.as_ref().map(OpaqueLabel::as_str)
                        != Some(session.as_str())
                {
                    return Ok(host_request_resolve_unresolved_response(
                        "conflict",
                        Some(&key),
                        None,
                    ));
                }
                Ok(host_request_resolved_response(&record, Some(&key)))
            }
            Some("operation-handle") => {
                let handle = resolve_text_field(object, "operation_handle")?;
                if envelope.identity.parent_operation_id.as_deref() != Some(handle.as_str()) {
                    return Err(TransportError::SessionFenced);
                }
                let (operation, digest) = resolve_handle_key(&handle)?;
                let stored = self
                    .generation_gateway
                    .ors
                    .load_host_request(&operation, &digest)
                    .map_err(|_| TransportError::SessionFenced)?;
                let Some(record) = stored else {
                    return Ok(host_request_resolve_unresolved_response(
                        "absent", None, None,
                    ));
                };
                if record.session_ref.as_ref().map(OpaqueLabel::as_str) != Some(session.as_str())
                    || require_current_generation_parent(&record, &descriptor).is_err()
                {
                    return Ok(host_request_resolve_unresolved_response(
                        "absent", None, None,
                    ));
                }
                let logical = RedbRecoveryStore::host_request_logical_key_for_record(&record)
                    .map_err(|_| TransportError::SessionFenced)?;
                Ok(host_request_resolved_response(&record, logical.as_deref()))
            }
            _ => Err(TransportError::SessionFenced),
        }
    }

    /// Fences every indexed host request after a bridge profile promotion.
    ///
    /// Promotion replaces the live profile and revokes all connections, so no
    /// presenting connection survives: every still-uncertain indexed operation
    /// is fenced to `Unknown` under the same owner-continuation rules as the
    /// per-connection fence. Like revocation, this never fails.
    pub(super) fn fence_all_host_requests(&self) -> Result<(), TransportError> {
        let (outstanding, poisoned) = match self.host_request_connection_index.lock() {
            Ok(mut index) => (
                std::mem::take(&mut *index)
                    .into_values()
                    .flatten()
                    .collect::<Vec<_>>(),
                false,
            ),
            Err(poisoned) => {
                let mut index = poisoned.into_inner();
                (
                    std::mem::take(&mut *index)
                        .into_values()
                        .flatten()
                        .collect::<Vec<_>>(),
                    true,
                )
            }
        };
        for operation_ref in &outstanding {
            fence_one_host_request(self, operation_ref);
        }
        if poisoned {
            Err(TransportError::SessionFenced)
        } else {
            Ok(())
        }
    }

    /// Fences the presenting connection's still-uncertain host requests.
    ///
    /// Called from disconnect revocation. Non-terminal records staged through
    /// the lost connection advance to `Unknown` so a later exact replay or
    /// reconciliation observes the disconnect instead of retrying blindly.
    /// Terminal records, and records that may already have produced effects
    /// beyond the pre-effect fence, stay under their owner's continuation
    /// rules. Revocation never fails: every store error is contained because
    /// fencing must hold even when the store is unavailable.
    pub(super) fn fence_host_requests_for_connection(&self, connection_id: &str) {
        let outstanding = match self.host_request_connection_index.lock() {
            Ok(mut index) => index.remove(connection_id).unwrap_or_default(),
            Err(poisoned) => {
                let mut index = poisoned.into_inner();
                index.remove(connection_id).unwrap_or_default()
            }
        };
        for operation_ref in &outstanding {
            fence_one_host_request(self, operation_ref);
        }
    }

    /// Verifies the envelope arrives on a currently retained bridge
    /// connection with a live accepted transport.
    ///
    /// Activation envelopes require a not-yet-activated connection inside its
    /// activation window; every other kind requires a completed activation
    /// with a live transport Session. Unknown connections fail closed, which
    /// is also the reconnect fence: a new connection identity never inherits
    /// the previous connection's admission.
    fn host_request_connection_gate_under_transition(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<
        (
            AgentBridgeAdmissionDescriptor,
            AgentBridgePeerAdmissionReceipt,
        ),
        TransportError,
    > {
        let now = unix_ms();
        let profile = self
            .agent_bridge_profile
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let state = connections
            .get(&envelope.connection_id)
            .ok_or(TransportError::SessionFenced)?;
        let receipt = state
            .accepted_transport
            .as_ref()
            .ok_or(TransportError::SessionFenced)?
            .admission_receipt()
            .clone();
        if receipt.connection_id != envelope.connection_id
            || receipt.descriptor_sha256 != profile.admission.descriptor_sha256
            || receipt.profile_id != profile.admission.profile_id.as_str()
            || receipt.state_fence != profile.admission.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        let session_live = state.session.is_some();
        let activation_done = state.activation_completed;
        match envelope.kind {
            HostRequestKind::Activation => {
                if activation_done || session_live {
                    return Err(TransportError::IdentityConflict);
                }
                if activation_deadline_expired(now, receipt.activation_deadline_unix_ms) {
                    return Err(TransportError::Timeout);
                }
            }
            HostRequestKind::Invocation
            | HostRequestKind::Cancellation
            | HostRequestKind::Status
            | HostRequestKind::Reconciliation => {
                if !activation_done || !session_live {
                    return Err(TransportError::SessionFenced);
                }
            }
        }
        Ok((profile.admission, receipt))
    }

    /// Applies the service-state rule that mirrors the admission gate: full
    /// admission requires `Ready`, while `Cancellation`, `Status`, and
    /// `Reconciliation` additionally route while `Degraded`. The gate itself
    /// re-enforces this rule; this check only orders the failure before any
    /// durable write.
    fn host_request_service_gate(
        &self,
        descriptor: &AgentBridgeAdmissionDescriptor,
        envelope: &HostRequestEnvelope,
    ) -> Result<(), TransportError> {
        let service_state = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .state();
        let degraded_admitted = matches!(
            envelope.kind,
            HostRequestKind::Cancellation
                | HostRequestKind::Status
                | HostRequestKind::Reconciliation
        );
        let admits = if degraded_admitted {
            matches!(
                service_state,
                KernelServiceState::Ready | KernelServiceState::Degraded
            )
        } else {
            service_state == KernelServiceState::Ready
        };
        if !admits {
            return Err(TransportError::SessionFenced);
        }
        if service_state == KernelServiceState::Ready {
            return self.validate_active_bridge_profile(descriptor);
        }
        // `Degraded` still routes `Cancellation`, `Status`, and
        // `Reconciliation` through the admission gate, so the candidate and
        // generation continuity below is enforced without the `Ready`-only
        // state line of the strict profile check.
        self.validate_bridge_profile_continuity(descriptor)
    }

    /// Verifies descriptor, candidate, and generation continuity without
    /// requiring the `Ready` service state.
    ///
    /// This repeats the exact field comparisons of the strict active-profile
    /// check minus its `Ready`-only state line, so degraded-routed kinds keep
    /// the same anti-stale-generation fence as full admission.
    fn validate_bridge_profile_continuity(
        &self,
        descriptor: &AgentBridgeAdmissionDescriptor,
    ) -> Result<(), TransportError> {
        let service = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if service.state() != KernelServiceState::Degraded {
            return Err(TransportError::SessionFenced);
        }
        let candidate = service
            .candidate_binding()
            .ok_or(TransportError::SessionFenced)?;
        if candidate.agent_bridge_admission.as_ref() != Some(descriptor) {
            return Err(TransportError::SessionFenced);
        }
        let activation = service
            .activation_receipt()
            .ok_or(TransportError::SessionFenced)?;
        if activation.generation != descriptor.generation
            || activation.authority_epoch != descriptor.authority_epoch
            || activation.candidate_binding_digest
                != candidate
                    .compute_digest()
                    .map_err(|_| TransportError::SessionFenced)?
            || descriptor.state_fence.resource_generation != activation.generation
            || descriptor.state_fence.authority_epoch != activation.authority_epoch
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Loads the exact retained typed resolution result for an Activation
    /// envelope without invoking the semantic resolver.
    ///
    /// The durable ORS lifecycle/result pair is the sole authority. A
    /// projected entry stays answerable because the exact ticket connection,
    /// lifecycle, and result payload remain in ORS. A missing ticket or a
    /// result-less lifecycle is an unknown operation; a result bound to
    /// another connection fails closed; a digest/fence mismatch is an identity
    /// conflict; a non-resolved disposition fails closed without yielding a
    /// binding.
    ///
    /// Every existing caller of this test-support wrapper is `#[cfg(windows)]`,
    /// so the gate matches the callers rather than the wider `#[cfg(test)]`
    /// main carried: on a non-Windows test build this wrapper would otherwise
    /// exist with no caller at all.
    #[cfg(all(test, windows))]
    pub(super) fn host_request_activation_resolution(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<AgentActivationResolutionResult, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        self.host_request_activation_resolution_under_transition(envelope)
    }

    fn host_request_activation_resolution_under_transition(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<AgentActivationResolutionResult, TransportError> {
        let activation_binding = envelope
            .activation_binding
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let lifecycle = self
            .generation_gateway
            .ors
            .load_activation_lifecycle(&activation_binding.ticket_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if lifecycle.connection_id != envelope.connection_id {
            return Err(TransportError::SessionFenced);
        }
        let result_sha256 = lifecycle
            .result_sha256
            .as_deref()
            .ok_or(TransportError::UnknownRequest)?;
        let retained = self
            .generation_gateway
            .ors
            .load_activation_result(&activation_binding.ticket_id, result_sha256)
            .map_err(|error| match error {
                OrsError::ActivationResultRetentionIdentityConflict { .. } => {
                    TransportError::IdentityConflict
                }
                _ => TransportError::SessionFenced,
            })?
            .ok_or(TransportError::UnknownRequest)?;
        let result: AgentActivationResolutionResult =
            serde_json::from_str(&retained.result_payload)
                .map_err(|_| TransportError::SessionFenced)?;
        result
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if result.ticket_id != activation_binding.ticket_id || result.result_sha256 != result_sha256
        {
            return Err(TransportError::IdentityConflict);
        }
        if result.resolved_binding().is_none() {
            return Err(TransportError::SessionFenced);
        }
        envelope
            .validate_resolution(&result)
            .map_err(|_| TransportError::IdentityConflict)?;
        Ok(result)
    }

    /// Advances the exact parent of a Cancellation envelope toward cancellation.
    ///
    /// The parent must be a known current-generation operation. Cancellation
    /// is attempted first; when the parent already passed the cancellable
    /// window the parent is fenced to `Unknown` instead so its outcome is
    /// reconciled rather than assumed. Parent advancement is best-effort: an
    /// illegal transition only means the parent lifecycle already moved on.
    fn advance_host_request_parent(
        &self,
        envelope: &HostRequestEnvelope,
        descriptor: &AgentBridgeAdmissionDescriptor,
    ) -> Result<(), TransportError> {
        // Serialize cancellation's parent transition against Observe queue
        // publication. Submit admission uses the same transition-read then
        // pending-owner order for its final durable-state reread and fill.
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let (parent_operation, parent_digest) = parent_operation_key(envelope)?;
        let parent = self
            .generation_gateway
            .ors
            .load_host_request(&parent_operation, &parent_digest)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        require_current_generation_parent(&parent, descriptor)?;
        if parent.state.is_terminal() {
            return Ok(());
        }
        match self.generation_gateway.ors.advance_host_request(
            &parent_operation,
            &parent_digest,
            HostRequestState::Cancelled,
            None,
        ) {
            Err(OrsError::InvalidTransition) => {
                let _ = self.generation_gateway.ors.advance_host_request(
                    &parent_operation,
                    &parent_digest,
                    HostRequestState::Unknown,
                    None,
                );
                Ok(())
            }
            Ok(_) | Err(_) => Ok(()),
        }
    }

    /// Requires the exact parent of a Status envelope to be known.
    ///
    /// Status is observation-only: the parent state is never advanced here.
    fn require_known_host_request_parent(
        &self,
        envelope: &HostRequestEnvelope,
        descriptor: &AgentBridgeAdmissionDescriptor,
    ) -> Result<(), TransportError> {
        let (parent_operation, parent_digest) = parent_operation_key(envelope)?;
        let parent = self
            .generation_gateway
            .ors
            .load_host_request(&parent_operation, &parent_digest)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        require_current_generation_parent(&parent, descriptor)
    }

    /// Moves an `Unknown` parent of a Reconciliation envelope to `Reconciling`.
    ///
    /// Parents in any other state are left to their owner's continuation
    /// rules; reconciliation never forces a transition the ORS table forbids.
    fn reconcile_host_request_parent(
        &self,
        envelope: &HostRequestEnvelope,
        descriptor: &AgentBridgeAdmissionDescriptor,
    ) -> Result<(), TransportError> {
        let (parent_operation, parent_digest) = parent_operation_key(envelope)?;
        let parent = self
            .generation_gateway
            .ors
            .load_host_request(&parent_operation, &parent_digest)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        require_current_generation_parent(&parent, descriptor)?;
        if parent.state == HostRequestState::Unknown {
            let _ = self.generation_gateway.ors.advance_host_request(
                &parent_operation,
                &parent_digest,
                HostRequestState::Reconciling,
                None,
            );
        }
        Ok(())
    }

    /// Indexes one staged operation under its presenting connection so
    /// disconnect revocation can fence it without enumerating the store.
    fn note_host_request_operation_under_transition(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<(), TransportError> {
        // The transition read guard is held by the enclosing host-request
        // ingress. Reacquire only the pending owner at the publication point:
        // the durable stage above may have crossed no profile promotion while
        // this guard is live, and this index entry is inserted before release.
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        self.host_request_connection_gate_under_transition(envelope)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = host_request_operation_id(envelope);
        if let Some(existing_connection) = index.iter().find_map(|(connection_id, refs)| {
            refs.iter()
                .find(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                })
                .map(|_| connection_id.as_str())
        }) {
            if existing_connection != envelope.connection_id {
                return Err(TransportError::IdentityConflict);
            }
        }
        let refs = index.entry(envelope.connection_id.clone()).or_default();
        if !refs.iter().any(|candidate| {
            candidate.operation_id == operation_id
                && candidate.request_digest == envelope.envelope_sha256
        }) {
            refs.push(HostRequestOperationRef {
                operation_id,
                request_digest: envelope.envelope_sha256.clone(),
                local_read_envelope: None,
                local_read_tool: None,
                local_read_attempt: LocalReadAttemptState::default(),
                observe_envelope: None,
                observe_tool: None,
                observe_reservation: None,
                observe_attempt: LocalReadAttemptState::default(),
                campaign_packet_envelope: None,
                campaign_packet_tool: None,
                campaign_packet_attempt: LocalReadAttemptState::default(),
                task_controller_envelope: None,
                task_controller_tool: None,
                task_controller_attempt: LocalReadAttemptState::default(),
            });
        }
        Ok(())
    }
}

/// Process-wide monotonic salt for local-read queue lifecycles.
///
/// Bumped at every enqueue so each queue lifecycle mints attempt identities
/// no earlier lifecycle can collide with, even when the fencing generation
/// restarts at 1 after retire or fence. Strictly increasing within a boot;
/// across restarts the composition boot nonce disambiguates.
static LOCAL_READ_ENQUEUE_SALT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl KernelComposition {
    /// Queues one admitted local-read pair for the daemon poller.
    ///
    /// Called best-effort from [`Self::invoke_read_host_request`] after the
    /// full admission gate, so only linkage-checked `eliot.query` pairs with
    /// valid selectors arrive here. An exact replay (same operation and
    /// digest already queued) is idempotent and never duplicates; when the
    /// bounded queue is full, only an unclaimed queued pair may be evicted
    /// (daemon-leg memory only — the durable ORS record is untouched). A full
    /// queue of claimed/in-flight attempts returns backpressure rather than
    /// silently stealing a live attempt.
    #[cfg(test)]
    pub(crate) fn enqueue_local_read_pair(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
    ) -> Result<(), TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        self.enqueue_local_read_pair_under_transition(envelope, tool)
    }

    fn enqueue_local_read_pair_under_transition(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
    ) -> Result<(), TransportError> {
        match check_local_read_admission(envelope, tool)? {
            LocalReadAdmission::Query(_) => {}
            LocalReadAdmission::CampaignPacket { .. } => {
                return Err(TransportError::SessionFenced);
            }
        }
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        self.host_request_connection_gate_under_transition(envelope)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = host_request_operation_id(envelope);
        let existing_connection = index.iter().find_map(|(connection_id, refs)| {
            refs.iter()
                .find(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                })
                .map(|_| connection_id.clone())
        });
        if let Some(existing_connection) = existing_connection.as_deref() {
            if existing_connection != envelope.connection_id {
                return Err(TransportError::IdentityConflict);
            }
            if index
                .get(existing_connection)
                .into_iter()
                .flatten()
                .any(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                        && candidate.local_read_envelope.is_some()
                })
            {
                return Ok(());
            }
        }
        let queued = index
            .values()
            .flatten()
            .filter(|candidate| candidate.local_read_envelope.is_some())
            .count();
        if queued >= MAX_QUEUED_LOCAL_READS {
            let mut evicted = false;
            for refs in index.values_mut() {
                if let Some(position) = refs.iter().position(|candidate| {
                    candidate.local_read_envelope.is_some()
                        && !candidate.local_read_attempt.is_live()
                }) {
                    refs.remove(position);
                    evicted = true;
                    break;
                }
            }
            if !evicted {
                return Err(TransportError::Backpressure);
            }
        }
        let refs = index.entry(envelope.connection_id.clone()).or_default();
        let local_read_attempt = LocalReadAttemptState {
            // The durable claim record is written at enqueue, before any
            // poll: unclaimed (`generation == 0`) until the first claim
            // mints fencing generation 1. The salt makes this lifecycle's
            // identities unique even if the pair is re-enqueued later. No
            // time lease is involved.
            enqueue_salt: LOCAL_READ_ENQUEUE_SALT.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            ..LocalReadAttemptState::default()
        };
        if let Some(candidate) = refs.iter_mut().find(|candidate| {
            candidate.operation_id == operation_id
                && candidate.request_digest == envelope.envelope_sha256
        }) {
            candidate.local_read_envelope = Some(envelope.clone());
            candidate.local_read_tool = Some(tool.clone());
            candidate.local_read_attempt = local_read_attempt;
        } else {
            refs.push(HostRequestOperationRef {
                operation_id,
                request_digest: envelope.envelope_sha256.clone(),
                local_read_envelope: Some(envelope.clone()),
                local_read_tool: Some(tool.clone()),
                local_read_attempt,
                observe_envelope: None,
                observe_tool: None,
                observe_reservation: None,
                observe_attempt: LocalReadAttemptState::default(),
                campaign_packet_envelope: None,
                campaign_packet_tool: None,
                campaign_packet_attempt: LocalReadAttemptState::default(),
                task_controller_envelope: None,
                task_controller_tool: None,
                task_controller_attempt: LocalReadAttemptState::default(),
            });
        }
        Ok(())
    }

    /// Claims the next admitted local-read pair for the daemon poller under
    /// governed attempt ownership.
    ///
    /// Deterministic connection-then-fifo order, skipping expired pairs and
    /// non-pairs. The first claim for a pair mints fencing generation 1 with
    /// a boot-unique attempt identity bound to the presenting daemon session;
    /// a re-claim by the same owner session returns the identical current
    /// capability (lost-answer retry without a new identity); a claim by a
    /// different owner reassigns the attempt (generation bump, fresh identity,
    /// new owner), so the superseded capability can never complete. `None` is
    /// a null poll, not an error. Pure queue memory: no store IO, so
    /// already-resulted pairs are retired by the submit legs rather than
    /// re-checked here.
    pub(crate) fn claim_local_read_pair(
        &self,
        session: &Session,
    ) -> Result<
        Option<(
            HostRequestEnvelope,
            serde_json::Value,
            eliot_protocol::LocalReadAttempt,
        )>,
        TransportError,
    > {
        let _transition = self.agent_bridge_transition_read()?;
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = unix_ms();
        // Deterministic order: `BTreeMap` iterates connections sorted, pairs
        // stay in enqueue (fifo) order within one connection.
        for refs in index.values_mut() {
            for candidate in refs.iter_mut() {
                let (Some(envelope), Some(tool)) = (
                    candidate.local_read_envelope.as_ref(),
                    candidate.local_read_tool.as_ref(),
                ) else {
                    continue;
                };
                if activation_deadline_expired(now, envelope.identity.deadline_unix_ms) {
                    continue;
                }
                if envelope.identity.capability != "eliot.query" {
                    continue;
                }
                if !candidate.local_read_attempt.is_owned_by(session) {
                    let generation = candidate
                        .local_read_attempt
                        .generation
                        .checked_add(1)
                        .ok_or(TransportError::SessionFenced)?;
                    candidate.local_read_attempt = LocalReadAttemptState {
                        attempt_id: self.mint_local_read_attempt_id(
                            &candidate.operation_id,
                            candidate.local_read_attempt.enqueue_salt,
                            generation,
                        ),
                        generation,
                        enqueue_salt: candidate.local_read_attempt.enqueue_salt,
                        owner_connection_id: session.connection_id.clone(),
                        owner_launch_nonce: session.launch_nonce.clone(),
                        owner_session_epoch: session.session_epoch,
                    };
                }
                let attempt = self.local_read_attempt_capability(
                    envelope,
                    &candidate.operation_id,
                    &candidate.local_read_attempt,
                )?;
                return Ok(Some((envelope.clone(), tool.clone(), attempt)));
            }
        }
        Ok(None)
    }

    /// Mints the boot-unique attempt identity for one fencing generation.
    ///
    /// Binds the exact operation handle, the per-composition boot nonce, the
    /// per-lifecycle enqueue salt, and the generation: the identity never
    /// repeats for another claim, another generation, another queue
    /// lifecycle, or another Kernel incarnation, so a capability serialized
    /// before a restart, retire, or fence can never match a claim record
    /// minted after it.
    fn mint_local_read_attempt_id(
        &self,
        operation_id: &str,
        enqueue_salt: u64,
        generation: u64,
    ) -> String {
        format!(
            "{operation_id}:attempt:{:016x}:{enqueue_salt}:{generation}",
            self.local_read_claim_boot_nonce
        )
    }

    /// Builds the fenced attempt capability for the live claim record.
    ///
    /// Every field is re-derived from the exact admitted envelope plus the
    /// live record: work-item handle, attempt identity, fencing generation,
    /// admitted session binding, authority epoch, trusted scope/facet method,
    /// absolute expiry, and single-use budget. A pair without a derivable
    /// trusted scope fails closed here and is skipped by the caller.
    /// Re-derivation is deterministic, so equality with a presented capability
    /// proves every echoed field is exactly what the Kernel minted.
    pub(crate) fn local_read_attempt_capability(
        &self,
        envelope: &HostRequestEnvelope,
        operation_id: &str,
        state: &LocalReadAttemptState,
    ) -> Result<eliot_protocol::LocalReadAttempt, TransportError> {
        let _ = self;
        let scope_text = envelope
            .identity
            .work_scope_id
            .as_deref()
            .filter(|scope| !scope.trim().is_empty())
            .or_else(|| {
                envelope
                    .identity
                    .session_id
                    .as_deref()
                    .filter(|scope| !scope.trim().is_empty())
            })
            .ok_or(TransportError::SessionFenced)?;
        let session_text = envelope
            .identity
            .session_id
            .as_deref()
            .filter(|session| !session.trim().is_empty())
            .or_else(|| {
                envelope
                    .identity
                    .work_scope_id
                    .as_deref()
                    .filter(|scope| !scope.trim().is_empty())
            })
            .unwrap_or(&envelope.connection_id);
        let attempt = LocalReadAttempt {
            wire_id: eliot_protocol::LOCAL_READ_ATTEMPT_WIRE_ID.to_owned(),
            wire_version: LocalReadAttempt::CONTRACT_VERSION,
            operation_id: operation_id.to_owned(),
            attempt_id: state.attempt_id.clone(),
            fencing_generation: state.generation,
            session_id: session_text.to_owned(),
            authority_epoch: envelope.state_fence.authority_epoch.clone(),
            scope_id: scope_text.to_owned(),
            facet_method: envelope.identity.capability.clone(),
            expires_at_unix_ms: envelope.identity.deadline_unix_ms,
            use_budget: 1,
        };
        attempt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(attempt)
    }

    /// Loads the live claim record for one operation without mutating it.
    ///
    /// Returns `None` when no queued pair exists (never claimed, retired, or
    /// fenced away). Pure queue memory: no store IO.
    pub(crate) fn live_local_read_attempt(
        &self,
        operation_id: &str,
        request_digest: &str,
    ) -> Result<Option<LocalReadAttemptState>, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        self.live_local_read_attempt_under_transition(operation_id, request_digest)
    }

    fn live_local_read_attempt_under_transition(
        &self,
        operation_id: &str,
        request_digest: &str,
    ) -> Result<Option<LocalReadAttemptState>, TransportError> {
        let index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(index
            .values()
            .flatten()
            .find(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.local_read_envelope.is_some()
            })
            .map(|candidate| candidate.local_read_attempt.clone())
            .filter(LocalReadAttemptState::is_live))
    }

    /// Retires one queued local-read pair without failing.
    ///
    /// Called after a result is persisted (submit and sync legs) so later
    /// claims skip it. Like disconnect fencing, this never fails: every
    /// lock/store error is contained because retirement must hold even when
    /// the store is unavailable.
    #[cfg(test)]
    pub(crate) fn retire_local_read_pair(&self, operation_id: &str, request_digest: &str) {
        let Ok(_transition) = self.agent_bridge_transition_read() else {
            return;
        };
        let Ok(_admission_owner) = self.agent_activation_pending.lock() else {
            return;
        };
        self.retire_local_read_pair_under_transition(operation_id, request_digest);
    }

    fn retire_local_read_pair_under_transition(&self, operation_id: &str, request_digest: &str) {
        let Ok(mut index) = self.host_request_connection_index.lock() else {
            return;
        };
        for refs in index.values_mut() {
            refs.retain(|candidate| {
                !(candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.local_read_envelope.is_some())
            });
        }
    }

    /// Submits one daemon-produced local-read result for its waiting host request.
    ///
    /// Validates the closed [`HostRequestResultBody`], binds it to the exact
    /// stored operation, then enforces governed attempt ownership: only the
    /// current fencing generation presented by the owning session may
    /// complete. A late, duplicate, mismatched, or revoked submission becomes
    /// a quarantined [`LocalReadSubmitDisposition::StaleAttempt`] observation
    /// with an audit receipt — the durable ORS record is untouched, so the
    /// waiter never observes the stale result — while the current attempt can
    /// still complete through its own bound capability.
    ///
    /// Check order is the safety argument: exact replay first (canonical
    /// readback, never a new completion), then the absolute deadline bound
    /// (expiry is [`TransportError::Timeout` — the expected race, projected
    /// as a known expired outcome by the daemon arm), then attempt currency
    /// (so lease replacement, restart, epoch rotation, and revocation project
    /// as stale before any fence join), then the presenting daemon session
    /// fence, then persistence through the ORS result path. Neither expiry
    /// nor staleness ever binds a result. A changed body under the same
    /// identity is [`TransportError::IdentityConflict`]; an unknown operation
    /// is [`TransportError::UnknownRequest`].
    #[allow(
        clippy::too_many_lines,
        reason = "the submit gate keeps replay, deadline, currency, fence, and persistence joins in one audited order"
    )]
    pub(crate) fn submit_local_read_result(
        &self,
        session: &Session,
        body: &HostRequestResultBody,
    ) -> Result<LocalReadSubmitDisposition, TransportError> {
        self.submit_claimed_result(session, body, DaemonReadQueue::Query)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the submit gate keeps replay, deadline, currency, fence, and persistence joins in one audited order"
    )]
    fn submit_claimed_result(
        &self,
        session: &Session,
        body: &HostRequestResultBody,
        queue: DaemonReadQueue,
    ) -> Result<LocalReadSubmitDisposition, TransportError> {
        body.validate().map_err(|_| TransportError::SessionFenced)?;
        let _transition = self.agent_bridge_transition_read()?;
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = OperationIdentity::new(body.operation_id.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let stored = self
            .generation_gateway
            .ors
            .load_host_request(&operation_id, &body.request_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if stored.operation_id.as_str() != body.operation_id
            || stored.request_digest != body.request_sha256
            || stored.capability_ref.as_str()
                != match queue {
                    DaemonReadQueue::Query => "eliot.query",
                    DaemonReadQueue::CampaignPacket => "eliot.packet",
                }
        {
            return Err(TransportError::SessionFenced);
        }
        // Exact replay is idempotent even across deadline expiry: a retained
        // terminal result never takes the expiry path, and serving it is
        // canonical readback rather than a second completion.
        if stored.state == HostRequestState::ResultReceived
            && stored.result_digest.as_deref() == Some(body.result_digest.as_str())
            && stored.result_response.as_ref() == Some(&body.response)
        {
            return Ok(LocalReadSubmitDisposition::Persisted(Box::new(stored)));
        }
        if activation_deadline_expired(unix_ms(), stored.deadline_unix_ms) {
            return Err(TransportError::Timeout);
        }
        // Governed attempt currency: only the live (attempt_id, generation,
        // owner) triple completes.
        let live = match queue {
            DaemonReadQueue::Query => self.live_local_read_attempt_under_transition(
                &body.operation_id,
                &body.request_sha256,
            )?,
            DaemonReadQueue::CampaignPacket => self.live_campaign_packet_attempt_under_transition(
                &body.operation_id,
                &body.request_sha256,
            )?,
        };
        match (&body.attempt, live) {
            (Some(attempt), Some(state))
                if attempt.attempt_id == state.attempt_id
                    && attempt.fencing_generation == state.generation =>
            {
                if !state.is_owned_by(session) {
                    return Ok(LocalReadSubmitDisposition::StaleAttempt(
                        StaleLocalReadObservation {
                            operation_id: body.operation_id.clone(),
                            request_digest: body.request_sha256.clone(),
                            presented_attempt_id: Some(attempt.attempt_id.clone()),
                            presented_generation: Some(attempt.fencing_generation),
                            current_generation: Some(state.generation),
                            reason: StaleLocalReadReason::OwnerMismatch,
                        },
                    ));
                }
                // The presented capability must echo the admitted bounds:
                // expiry is the stored absolute deadline and the epoch is the
                // stored authority. A substituted echo is not the current
                // valid attempt, even with a matching identity.
                if attempt.expires_at_unix_ms != stored.deadline_unix_ms
                    || !attempt
                        .authority_epoch
                        .is_same_authority(&stored.authority_epoch)
                {
                    return Ok(LocalReadSubmitDisposition::StaleAttempt(
                        StaleLocalReadObservation {
                            operation_id: body.operation_id.clone(),
                            request_digest: body.request_sha256.clone(),
                            presented_attempt_id: Some(attempt.attempt_id.clone()),
                            presented_generation: Some(attempt.fencing_generation),
                            current_generation: Some(state.generation),
                            reason: StaleLocalReadReason::Superseded,
                        },
                    ));
                }
            }
            (Some(attempt), Some(state)) => {
                return Ok(LocalReadSubmitDisposition::StaleAttempt(
                    StaleLocalReadObservation {
                        operation_id: body.operation_id.clone(),
                        request_digest: body.request_sha256.clone(),
                        presented_attempt_id: Some(attempt.attempt_id.clone()),
                        presented_generation: Some(attempt.fencing_generation),
                        current_generation: Some(state.generation),
                        reason: StaleLocalReadReason::Superseded,
                    },
                ));
            }
            (presented, current) => {
                return Ok(LocalReadSubmitDisposition::StaleAttempt(
                    StaleLocalReadObservation {
                        operation_id: body.operation_id.clone(),
                        request_digest: body.request_sha256.clone(),
                        presented_attempt_id: presented
                            .as_ref()
                            .map(|attempt| attempt.attempt_id.clone()),
                        presented_generation: presented
                            .as_ref()
                            .map(|attempt| attempt.fencing_generation),
                        current_generation: current.map(|state| state.generation),
                        reason: StaleLocalReadReason::Unclaimed,
                    },
                ));
            }
        }
        if activation_deadline_expired(unix_ms(), stored.deadline_unix_ms) {
            return Err(TransportError::Timeout);
        }
        let queued_envelope = {
            let index = self
                .host_request_connection_index
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            index
                .values()
                .flatten()
                .find(|candidate| {
                    candidate.operation_id == body.operation_id
                        && candidate.request_digest == body.request_sha256
                })
                .and_then(|candidate| match queue {
                    DaemonReadQueue::Query => candidate.local_read_envelope.clone(),
                    DaemonReadQueue::CampaignPacket => candidate.campaign_packet_envelope.clone(),
                })
        };
        validate_campaign_view_result(&stored, queued_envelope.as_ref(), &body.response)?;
        if let Some(envelope) = queued_envelope {
            if !session
                .authority_epoch
                .is_same_authority(&envelope.state_fence.authority_epoch)
                || session.module_generation.generation != envelope.state_fence.resource_generation
                || session.module_generation.state_fence != envelope.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
        } else if !session
            .authority_epoch
            .is_same_authority(&stored.authority_epoch)
            || session.module_generation.generation.value() != stored.generation
        {
            return Err(TransportError::SessionFenced);
        }
        let persisted = self
            .generation_gateway
            .ors
            .persist_host_request_result(
                &operation_id,
                &body.request_sha256,
                &body.result_digest,
                &body.response,
            )
            .map_err(|error| match error {
                OrsError::HostRequestIdentityConflict { .. } => TransportError::IdentityConflict,
                _ => TransportError::SessionFenced,
            })?
            .ok_or(TransportError::UnknownRequest)?;
        // The single completion consumes the attempt use budget: retire the
        // pair in the same queue ledger that authorized it so no later claim
        // or submit can reuse this generation.
        match queue {
            DaemonReadQueue::Query => {
                self.retire_local_read_pair_under_transition(
                    &body.operation_id,
                    &body.request_sha256,
                );
            }
            DaemonReadQueue::CampaignPacket => {
                self.retire_campaign_packet_pair_under_transition(
                    &body.operation_id,
                    &body.request_sha256,
                );
            }
        }
        Ok(LocalReadSubmitDisposition::Persisted(Box::new(persisted)))
    }
}

/// Closed capability admitted to the observe queue (issue #2565: one
/// complete Observe path through the daemon owner).
///
/// Only `eliot.observe` invocations carrying their exact linked tool bytes
/// enqueue here. Every other capability keeps its existing entry untouched:
/// `eliot.query` rides the local-read pair above, digest-only submits stay
/// admission-only, and a forged capability fails the linkage gate before any
/// staging.
pub(crate) const OBSERVE_CAPABILITY: &str = "eliot.observe";

/// Bound on queued observe pairs for the daemon observe poller.
///
/// Mirrors the bounded local-read queue (64): the durable ORS record owns
/// lifecycle state, so eviction only drops daemon-leg queue memory and never
/// fabricates admission.
const MAX_QUEUED_OBSERVE_PAIRS: usize = 64;

/// Bound on retained observe tool bytes per queued pair.
///
/// Tool bytes live in queue memory only — never persisted, never logged —
/// so privacy validation precedes any durable write by construction: there
/// is none. The ceiling keeps one pair under the transport frame budget
/// without trusting the caller-declared size.
const MAX_OBSERVE_TOOL_BYTES: usize = 64 * 1024;

/// Process-wide monotonic salt for observe queue lifecycles.
///
/// Separate from the local-read salt so the two legs never share a lifecycle
/// namespace even though they share the attempt-identity vehicle and boot
/// nonce: a capability minted for a local-read lifecycle can never match an
/// observe claim record and vice versa.
static OBSERVE_ENQUEUE_SALT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static OBSERVE_RESERVATION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

enum ObserveQueueReservation {
    ExistingQueued,
    Reserved { token: u64, had_reference: bool },
}

fn next_observe_reservation() -> Result<u64, TransportError> {
    OBSERVE_RESERVATION_ID
        .fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |current| current.checked_add(1),
        )
        .map_err(|_| TransportError::Backpressure)
}

/// Disposition of one daemon observe-poller deferral.
///
/// `Deferred` is the single honest outcome while the Governor observation
/// owner has no connected MCP-observe admission: the queue pair is consumed
/// and the durable ORS record advances `Admitted -> Routed`, so the pending
/// handle stays live under the daemon owner with its exact resume condition
/// (resubmit the same logical request once the owner connects; the
/// status/resolve/rehydrate entries keep serving the live record meanwhile).
/// `Settled` means the durable record already closed the operation — consult
/// it instead of deferring. `StaleAttempt` quarantines a late, duplicate,
/// mismatched, or revoked deferral exactly like the submit leg.
#[derive(Clone, Debug)]
pub(crate) enum ObserveDeferDisposition {
    Deferred(Box<HostRequestRecord>),
    Settled(Box<HostRequestRecord>),
    StaleAttempt(StaleLocalReadObservation),
}

/// Validates one observe tool linkage before any staging (no IO).
///
/// Runs the exact shared linkage gate ([`HostRequestInvokeReadPayload`]:
/// capability echoes the admitted tool name, canonical tool bytes digest to
/// the admitted payload digest) plus the observe capability join and the
/// retained-bytes bound. A changed payload digest, a forged capability, or
/// over-bound bytes fail closed as `SessionFenced` before the caller stages
/// anything. Pure: validation performs no IO by construction, which is the
/// rejection-before-staging proof. The Kernel never interprets observe
/// semantics here — only the closed linkage shape.
pub(crate) fn check_observe_tool_linkage(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<(), TransportError> {
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|_| TransportError::SessionFenced)?;
    if envelope.identity.capability != OBSERVE_CAPABILITY {
        return Err(TransportError::SessionFenced);
    }
    let bytes = serde_json::to_vec(tool).map_err(|_| TransportError::SessionFenced)?;
    if bytes.is_empty() || bytes.len() > MAX_OBSERVE_TOOL_BYTES {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

impl KernelComposition {
    /// Admits a host request and atomically hands linked Observe input to the
    /// bounded daemon queue before the caller may acknowledge it.
    pub(crate) fn admit_and_queue_observe_submit(
        &self,
        envelope: &HostRequestEnvelope,
        tool: Option<&serde_json::Value>,
    ) -> Result<(HostRequestAdmissionReceipt, HostRequestRecord), TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        if envelope.identity.capability == OBSERVE_CAPABILITY
            && let Some(tool) = tool
        {
            check_observe_tool_linkage(envelope, tool)?;
        }
        let is_observe = envelope.identity.capability == OBSERVE_CAPABILITY
            && envelope.kind == HostRequestKind::Invocation;
        let Some(tool) = tool.filter(|_| is_observe) else {
            return self.admit_host_request_envelope_under_transition(envelope);
        };
        self.host_request_connection_gate_under_transition(envelope)?;

        let operation = OperationIdentity::new(host_request_operation_id(envelope))
            .map_err(|_| TransportError::SessionFenced)?;
        let existing = self
            .generation_gateway
            .ors
            .load_host_request(&operation, &envelope.envelope_sha256)
            .map_err(|_| TransportError::SessionFenced)?;
        if existing.as_ref().is_some_and(|record| {
            record.state.is_terminal()
                || matches!(
                    record.state,
                    HostRequestState::Submitted
                        | HostRequestState::PossiblyEffected
                        | HostRequestState::Unknown
                        | HostRequestState::Reconciling
                )
        }) {
            let admitted = self.admit_host_request_envelope_under_transition(envelope)?;
            self.remove_observe_pair_if_not_executable(
                admitted.1.operation_id.as_str(),
                &envelope.envelope_sha256,
                &admitted.1,
            )?;
            return Ok(admitted);
        }

        let operation_id = operation.as_str().to_owned();
        let reservation = self.reserve_observe_queue_slot(envelope, &operation_id)?;

        let admitted = match self.admit_host_request_envelope_under_transition(envelope) {
            Ok(admitted) => admitted,
            Err(error) => {
                if let ObserveQueueReservation::Reserved {
                    token,
                    had_reference,
                } = reservation
                {
                    self.rollback_observe_reservation(
                        &operation_id,
                        &envelope.envelope_sha256,
                        token,
                        had_reference,
                    );
                }
                return Err(error);
            }
        };
        match reservation {
            ObserveQueueReservation::ExistingQueued => {
                self.finish_existing_observe_replay(envelope, admitted)
            }
            ObserveQueueReservation::Reserved {
                token,
                had_reference,
            } => self.fill_observe_reservation(envelope, tool, token, had_reference, admitted),
        }
    }

    fn reserve_observe_queue_slot(
        &self,
        envelope: &HostRequestEnvelope,
        operation_id: &str,
    ) -> Result<ObserveQueueReservation, TransportError> {
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let existing_connection = index.iter().find_map(|(connection_id, refs)| {
            refs.iter()
                .find(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                })
                .map(|_| connection_id.clone())
        });
        if existing_connection
            .as_deref()
            .is_some_and(|connection_id| connection_id != envelope.connection_id)
        {
            return Err(TransportError::IdentityConflict);
        }
        if let Some(position) = index
            .get(&envelope.connection_id)
            .into_iter()
            .flatten()
            .position(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.request_digest == envelope.envelope_sha256
            })
        {
            let candidate = index
                .get(&envelope.connection_id)
                .and_then(|refs| refs.get(position))
                .ok_or(TransportError::SessionFenced)?;
            if candidate.observe_envelope.is_some() {
                return Ok(ObserveQueueReservation::ExistingQueued);
            }
            if candidate.observe_reservation.is_some() {
                return Err(TransportError::Backpressure);
            }
            Self::require_observe_queue_capacity(&index)?;
            let token = next_observe_reservation()?;
            index
                .get_mut(&envelope.connection_id)
                .and_then(|refs| refs.get_mut(position))
                .ok_or(TransportError::SessionFenced)?
                .observe_reservation = Some(token);
            return Ok(ObserveQueueReservation::Reserved {
                token,
                had_reference: true,
            });
        }

        Self::require_observe_queue_capacity(&index)?;
        let token = next_observe_reservation()?;
        index
            .entry(envelope.connection_id.clone())
            .or_default()
            .push(HostRequestOperationRef {
                operation_id: operation_id.to_owned(),
                request_digest: envelope.envelope_sha256.clone(),
                local_read_envelope: None,
                local_read_tool: None,
                local_read_attempt: LocalReadAttemptState::default(),
                observe_envelope: None,
                observe_tool: None,
                observe_reservation: Some(token),
                observe_attempt: LocalReadAttemptState::default(),
                campaign_packet_envelope: None,
                campaign_packet_tool: None,
                campaign_packet_attempt: LocalReadAttemptState::default(),
                task_controller_envelope: None,
                task_controller_tool: None,
                task_controller_attempt: LocalReadAttemptState::default(),
            });
        Ok(ObserveQueueReservation::Reserved {
            token,
            had_reference: false,
        })
    }

    fn require_observe_queue_capacity(
        index: &std::collections::BTreeMap<String, Vec<HostRequestOperationRef>>,
    ) -> Result<(), TransportError> {
        let queued = index
            .values()
            .flatten()
            .filter(|candidate| {
                candidate.observe_envelope.is_some() || candidate.observe_reservation.is_some()
            })
            .count();
        if queued >= MAX_QUEUED_OBSERVE_PAIRS {
            Err(TransportError::Backpressure)
        } else {
            Ok(())
        }
    }

    fn rollback_observe_reservation(
        &self,
        operation_id: &str,
        request_digest: &str,
        token: u64,
        had_reference: bool,
    ) {
        let Ok(_admission_owner) = self.agent_activation_pending.lock() else {
            return;
        };
        let Ok(mut index) = self.host_request_connection_index.lock() else {
            return;
        };
        for refs in index.values_mut() {
            if let Some(position) = refs.iter().position(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.observe_reservation == Some(token)
            }) {
                if had_reference {
                    refs[position].observe_reservation = None;
                } else {
                    refs.remove(position);
                }
                break;
            }
        }
    }

    fn fill_observe_reservation(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
        token: u64,
        had_reference: bool,
        admitted: (HostRequestAdmissionReceipt, HostRequestRecord),
    ) -> Result<(HostRequestAdmissionReceipt, HostRequestRecord), TransportError> {
        let admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation = admitted.1.operation_id.clone();
        let current = match self
            .generation_gateway
            .ors
            .load_host_request(&operation, &envelope.envelope_sha256)
        {
            Ok(Some(current)) => current,
            Ok(None) => {
                drop(admission_owner);
                self.rollback_observe_reservation(
                    admitted.1.operation_id.as_str(),
                    &envelope.envelope_sha256,
                    token,
                    had_reference,
                );
                return Err(TransportError::UnknownRequest);
            }
            Err(_) => {
                drop(admission_owner);
                self.rollback_observe_reservation(
                    admitted.1.operation_id.as_str(),
                    &envelope.envelope_sha256,
                    token,
                    had_reference,
                );
                return Err(TransportError::SessionFenced);
            }
        };
        let executable = matches!(
            current.state,
            HostRequestState::Admitted | HostRequestState::Routed
        ) && current.result_digest.is_none()
            && current.result_response.is_none();
        let retained_result = current.state == HostRequestState::ResultReceived
            && current.result_digest.is_some()
            && current.result_response.is_some();
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let refs = index
            .get_mut(&envelope.connection_id)
            .ok_or(TransportError::SessionFenced)?;
        let position = refs
            .iter()
            .position(|candidate| {
                candidate.operation_id.as_str() == admitted.1.operation_id.as_str()
                    && candidate.request_digest == envelope.envelope_sha256
                    && candidate.observe_reservation == Some(token)
            })
            .ok_or(TransportError::SessionFenced)?;
        if executable {
            let candidate = &mut refs[position];
            candidate.observe_reservation = None;
            candidate.observe_envelope = Some(envelope.clone());
            candidate.observe_tool = Some(tool.clone());
            candidate.observe_attempt = LocalReadAttemptState {
                enqueue_salt: OBSERVE_ENQUEUE_SALT
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                ..LocalReadAttemptState::default()
            };
        } else if had_reference {
            refs[position].observe_reservation = None;
        } else {
            refs.remove(position);
        }
        if executable {
            Ok(admitted)
        } else if retained_result {
            Ok((admitted.0, current))
        } else {
            Err(TransportError::SessionFenced)
        }
    }

    fn finish_existing_observe_replay(
        &self,
        envelope: &HostRequestEnvelope,
        admitted: (HostRequestAdmissionReceipt, HostRequestRecord),
    ) -> Result<(HostRequestAdmissionReceipt, HostRequestRecord), TransportError> {
        self.remove_observe_pair_if_not_executable(
            admitted.1.operation_id.as_str(),
            &envelope.envelope_sha256,
            &admitted.1,
        )?;
        Ok(admitted)
    }

    fn remove_observe_pair_if_not_executable(
        &self,
        operation_id: &str,
        request_digest: &str,
        record: &HostRequestRecord,
    ) -> Result<(), TransportError> {
        if matches!(
            record.state,
            HostRequestState::Admitted | HostRequestState::Routed
        ) && record.result_digest.is_none()
            && record.result_response.is_none()
        {
            return Ok(());
        }
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        for refs in index.values_mut() {
            refs.retain(|candidate| {
                !(candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.observe_envelope.is_some())
            });
        }
        Ok(())
    }

    /// Claims the next admitted observe pair for the daemon observe poller
    /// under governed attempt ownership.
    ///
    /// Deterministic connection-then-fifo order, skipping expired pairs and
    /// non-pairs. The first claim for a pair mints fencing generation 1 with
    /// a boot-unique attempt identity bound to the presenting daemon session;
    /// a re-claim by the same owner session returns the identical current
    /// capability (lost-answer retry without a new identity); a claim by a
    /// different owner reassigns the attempt (generation bump, fresh identity,
    /// new owner), so the superseded capability can never complete. `None` is
    /// a null poll, not an error. Pure queue memory: no store IO, so
    /// already-resulted pairs are retired by the submit/defer legs rather
    /// than re-checked here. Local-read pairs are never served here.
    pub(crate) fn claim_observe_pair(
        &self,
        session: &Session,
    ) -> Result<
        Option<(
            HostRequestEnvelope,
            serde_json::Value,
            eliot_protocol::LocalReadAttempt,
        )>,
        TransportError,
    > {
        let _transition = self.agent_bridge_transition_read()?;
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = unix_ms();
        // Deterministic order: `BTreeMap` iterates connections sorted, pairs
        // stay in enqueue (fifo) order within one connection.
        for refs in index.values_mut() {
            for candidate in refs.iter_mut() {
                let (Some(envelope), Some(tool)) = (
                    candidate.observe_envelope.as_ref(),
                    candidate.observe_tool.as_ref(),
                ) else {
                    continue;
                };
                if activation_deadline_expired(now, envelope.identity.deadline_unix_ms) {
                    continue;
                }
                if envelope.identity.capability != OBSERVE_CAPABILITY {
                    continue;
                }
                if !candidate.observe_attempt.is_owned_by(session) {
                    let generation = candidate
                        .observe_attempt
                        .generation
                        .checked_add(1)
                        .ok_or(TransportError::SessionFenced)?;
                    candidate.observe_attempt = LocalReadAttemptState {
                        attempt_id: self.mint_local_read_attempt_id(
                            &candidate.operation_id,
                            candidate.observe_attempt.enqueue_salt,
                            generation,
                        ),
                        generation,
                        enqueue_salt: candidate.observe_attempt.enqueue_salt,
                        owner_connection_id: session.connection_id.clone(),
                        owner_launch_nonce: session.launch_nonce.clone(),
                        owner_session_epoch: session.session_epoch,
                    };
                }
                let attempt = self.local_read_attempt_capability(
                    envelope,
                    &candidate.operation_id,
                    &candidate.observe_attempt,
                )?;
                return Ok(Some((envelope.clone(), tool.clone(), attempt)));
            }
        }
        Ok(None)
    }

    fn live_observe_attempt_under_transition(
        &self,
        operation_id: &str,
        request_digest: &str,
    ) -> Result<Option<LocalReadAttemptState>, TransportError> {
        let index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(index
            .values()
            .flatten()
            .find(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.observe_envelope.is_some()
            })
            .map(|candidate| candidate.observe_attempt.clone())
            .filter(LocalReadAttemptState::is_live))
    }

    /// Retires one queued observe pair without failing.
    ///
    /// Called after a result persists (submit leg) or after the daemon flight
    /// honestly defers the pair (defer leg advances the durable ORS phase, so
    /// the pending handle stays live without the queue entry), so later
    /// claims skip it. Like disconnect fencing, this never fails: every
    /// lock/store error is contained because retirement must hold even when
    /// the store is unavailable.
    fn retire_observe_pair_under_transition(&self, operation_id: &str, request_digest: &str) {
        let Ok(mut index) = self.host_request_connection_index.lock() else {
            return;
        };
        for refs in index.values_mut() {
            refs.retain(|candidate| {
                !(candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.observe_envelope.is_some())
            });
        }
    }

    /// Submits one daemon-produced observe result for its waiting host request.
    ///
    /// Mirrors [`Self::submit_local_read_result`] over the observe queue:
    /// exact replay first (canonical readback, never a new completion), then
    /// the absolute deadline bound, then attempt currency (lease replacement,
    /// restart, epoch rotation, and revocation project as stale before any
    /// fence join), then the presenting daemon session fence, then
    /// persistence through the ORS result path (which walks the mechanical
    /// `Admitted -> Routed -> Submitted -> ResultReceived` lifecycle — no new
    /// edge). Neither expiry nor staleness ever binds a result. A changed
    /// body under the same identity is [`TransportError::IdentityConflict`];
    /// an unknown operation is [`TransportError::UnknownRequest`]. The shared
    /// governed-attempt vehicle carries the disposition; the wire capability
    /// disambiguates through its admitted `facet_method`.
    #[allow(
        clippy::too_many_lines,
        reason = "the submit gate keeps replay, deadline, currency, fence, and persistence joins in one audited order"
    )]
    pub(crate) fn submit_observe_result(
        &self,
        session: &Session,
        body: &HostRequestResultBody,
    ) -> Result<LocalReadSubmitDisposition, TransportError> {
        body.validate().map_err(|_| TransportError::SessionFenced)?;
        let _transition = self.agent_bridge_transition_read()?;
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = OperationIdentity::new(body.operation_id.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let stored = self
            .generation_gateway
            .ors
            .load_host_request(&operation_id, &body.request_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if stored.operation_id.as_str() != body.operation_id
            || stored.request_digest != body.request_sha256
        {
            return Err(TransportError::SessionFenced);
        }
        // Exact replay is idempotent even across deadline expiry: a retained
        // terminal result never takes the expiry path, and serving it is
        // canonical readback rather than a second completion.
        if stored.state == HostRequestState::ResultReceived
            && stored.result_digest.as_deref() == Some(body.result_digest.as_str())
            && stored.result_response.as_ref() == Some(&body.response)
        {
            return Ok(LocalReadSubmitDisposition::Persisted(Box::new(stored)));
        }
        if activation_deadline_expired(unix_ms(), stored.deadline_unix_ms) {
            return Err(TransportError::Timeout);
        }
        // Governed attempt currency: only the live (attempt_id, generation,
        // owner) triple completes.
        let live =
            self.live_observe_attempt_under_transition(&body.operation_id, &body.request_sha256)?;
        match (&body.attempt, live) {
            (Some(attempt), Some(state))
                if attempt.attempt_id == state.attempt_id
                    && attempt.fencing_generation == state.generation =>
            {
                if !state.is_owned_by(session) {
                    return Ok(LocalReadSubmitDisposition::StaleAttempt(
                        StaleLocalReadObservation {
                            operation_id: body.operation_id.clone(),
                            request_digest: body.request_sha256.clone(),
                            presented_attempt_id: Some(attempt.attempt_id.clone()),
                            presented_generation: Some(attempt.fencing_generation),
                            current_generation: Some(state.generation),
                            reason: StaleLocalReadReason::OwnerMismatch,
                        },
                    ));
                }
                if attempt.expires_at_unix_ms != stored.deadline_unix_ms
                    || !attempt
                        .authority_epoch
                        .is_same_authority(&stored.authority_epoch)
                {
                    return Ok(LocalReadSubmitDisposition::StaleAttempt(
                        StaleLocalReadObservation {
                            operation_id: body.operation_id.clone(),
                            request_digest: body.request_sha256.clone(),
                            presented_attempt_id: Some(attempt.attempt_id.clone()),
                            presented_generation: Some(attempt.fencing_generation),
                            current_generation: Some(state.generation),
                            reason: StaleLocalReadReason::Superseded,
                        },
                    ));
                }
            }
            (Some(attempt), Some(state)) => {
                return Ok(LocalReadSubmitDisposition::StaleAttempt(
                    StaleLocalReadObservation {
                        operation_id: body.operation_id.clone(),
                        request_digest: body.request_sha256.clone(),
                        presented_attempt_id: Some(attempt.attempt_id.clone()),
                        presented_generation: Some(attempt.fencing_generation),
                        current_generation: Some(state.generation),
                        reason: StaleLocalReadReason::Superseded,
                    },
                ));
            }
            (presented, current) => {
                return Ok(LocalReadSubmitDisposition::StaleAttempt(
                    StaleLocalReadObservation {
                        operation_id: body.operation_id.clone(),
                        request_digest: body.request_sha256.clone(),
                        presented_attempt_id: presented
                            .as_ref()
                            .map(|attempt| attempt.attempt_id.clone()),
                        presented_generation: presented
                            .as_ref()
                            .map(|attempt| attempt.fencing_generation),
                        current_generation: current.map(|state| state.generation),
                        reason: StaleLocalReadReason::Unclaimed,
                    },
                ));
            }
        }
        if activation_deadline_expired(unix_ms(), stored.deadline_unix_ms) {
            return Err(TransportError::Timeout);
        }
        let queued_envelope = {
            let index = self
                .host_request_connection_index
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            index
                .values()
                .flatten()
                .find(|candidate| {
                    candidate.operation_id == body.operation_id
                        && candidate.request_digest == body.request_sha256
                })
                .and_then(|candidate| candidate.observe_envelope.clone())
        };
        if let Some(envelope) = queued_envelope {
            if !session
                .authority_epoch
                .is_same_authority(&envelope.state_fence.authority_epoch)
                || session.module_generation.generation != envelope.state_fence.resource_generation
                || session.module_generation.state_fence != envelope.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
        } else if !session
            .authority_epoch
            .is_same_authority(&stored.authority_epoch)
            || session.module_generation.generation.value() != stored.generation
        {
            return Err(TransportError::SessionFenced);
        }
        let persisted = self
            .generation_gateway
            .ors
            .persist_host_request_result(
                &operation_id,
                &body.request_sha256,
                &body.result_digest,
                &body.response,
            )
            .map_err(|error| match error {
                OrsError::HostRequestIdentityConflict { .. } => TransportError::IdentityConflict,
                _ => TransportError::SessionFenced,
            })?
            .ok_or(TransportError::UnknownRequest)?;
        // The single completion consumes the attempt use budget: retire the
        // pair so no later claim or submit can reuse this generation.
        self.retire_observe_pair_under_transition(&body.operation_id, &body.request_sha256);
        Ok(LocalReadSubmitDisposition::Persisted(Box::new(persisted)))
    }

    /// Defers one claimed observe pair the daemon flight cannot execute yet.
    ///
    /// The presenting attempt must be the live (`attempt_id`, generation,
    /// owner) triple: a late, duplicate, mismatched, or revoked deferral
    /// quarantines as [`ObserveDeferDisposition::StaleAttempt`] without
    /// touching the durable record. A terminal record settles as
    /// [`ObserveDeferDisposition::Settled`] — the waiter path serves its
    /// truth. Otherwise the durable ORS record advances `Admitted -> Routed`
    /// (already-`Routed` replays idempotently; any other live state fails
    /// closed) and the queue pair retires, so the pending handle stays live
    /// under the daemon owner with its exact resume condition while no queue
    /// entry spins. An exact resubmit re-enqueues through the submit arm, so
    /// the pair becomes claimable again once the Governor observation owner
    /// connects its admission — without ever duplicating an effect, because
    /// no effect was produced.
    #[allow(
        clippy::too_many_lines,
        reason = "the defer gate keeps terminal, deadline, currency, fence, and phase-advance joins in one audited order"
    )]
    pub(crate) fn defer_observe_claim(
        &self,
        session: &Session,
        operation_id: &str,
        request_digest: &str,
        attempt: &eliot_protocol::LocalReadAttempt,
    ) -> Result<ObserveDeferDisposition, TransportError> {
        attempt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let _transition = self.agent_bridge_transition_read()?;
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation = OperationIdentity::new(operation_id.to_owned())
            .map_err(|_| TransportError::SessionFenced)?;
        let stored = self
            .generation_gateway
            .ors
            .load_host_request(&operation, request_digest)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if stored.operation_id.as_str() != operation_id || stored.request_digest != request_digest {
            return Err(TransportError::SessionFenced);
        }
        if stored.state.is_terminal() {
            return Ok(ObserveDeferDisposition::Settled(Box::new(stored)));
        }
        if activation_deadline_expired(unix_ms(), stored.deadline_unix_ms) {
            return Err(TransportError::Timeout);
        }
        let live = self.live_observe_attempt_under_transition(operation_id, request_digest)?;
        match live {
            Some(state)
                if attempt.attempt_id == state.attempt_id
                    && attempt.fencing_generation == state.generation =>
            {
                if !state.is_owned_by(session) {
                    return Ok(ObserveDeferDisposition::StaleAttempt(
                        StaleLocalReadObservation {
                            operation_id: operation_id.to_owned(),
                            request_digest: request_digest.to_owned(),
                            presented_attempt_id: Some(attempt.attempt_id.clone()),
                            presented_generation: Some(attempt.fencing_generation),
                            current_generation: Some(state.generation),
                            reason: StaleLocalReadReason::OwnerMismatch,
                        },
                    ));
                }
                if attempt.expires_at_unix_ms != stored.deadline_unix_ms
                    || !attempt
                        .authority_epoch
                        .is_same_authority(&stored.authority_epoch)
                {
                    return Ok(ObserveDeferDisposition::StaleAttempt(
                        StaleLocalReadObservation {
                            operation_id: operation_id.to_owned(),
                            request_digest: request_digest.to_owned(),
                            presented_attempt_id: Some(attempt.attempt_id.clone()),
                            presented_generation: Some(attempt.fencing_generation),
                            current_generation: Some(state.generation),
                            reason: StaleLocalReadReason::Superseded,
                        },
                    ));
                }
            }
            Some(state) => {
                return Ok(ObserveDeferDisposition::StaleAttempt(
                    StaleLocalReadObservation {
                        operation_id: operation_id.to_owned(),
                        request_digest: request_digest.to_owned(),
                        presented_attempt_id: Some(attempt.attempt_id.clone()),
                        presented_generation: Some(attempt.fencing_generation),
                        current_generation: Some(state.generation),
                        reason: StaleLocalReadReason::Superseded,
                    },
                ));
            }
            None => {
                return Ok(ObserveDeferDisposition::StaleAttempt(
                    StaleLocalReadObservation {
                        operation_id: operation_id.to_owned(),
                        request_digest: request_digest.to_owned(),
                        presented_attempt_id: Some(attempt.attempt_id.clone()),
                        presented_generation: Some(attempt.fencing_generation),
                        current_generation: None,
                        reason: StaleLocalReadReason::Unclaimed,
                    },
                ));
            }
        }
        let queued_envelope = {
            let index = self
                .host_request_connection_index
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            index
                .values()
                .flatten()
                .find(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == request_digest
                })
                .and_then(|candidate| candidate.observe_envelope.clone())
        };
        if let Some(envelope) = queued_envelope {
            if !session
                .authority_epoch
                .is_same_authority(&envelope.state_fence.authority_epoch)
                || session.module_generation.generation != envelope.state_fence.resource_generation
                || session.module_generation.state_fence != envelope.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
        } else if !session
            .authority_epoch
            .is_same_authority(&stored.authority_epoch)
            || session.module_generation.generation.value() != stored.generation
        {
            return Err(TransportError::SessionFenced);
        }
        let routed = match stored.state {
            HostRequestState::Admitted => self
                .generation_gateway
                .ors
                .advance_host_request(&operation, request_digest, HostRequestState::Routed, None)
                .map_err(|_| TransportError::SessionFenced)?
                .ok_or(TransportError::UnknownRequest)?,
            HostRequestState::Routed => stored,
            _ => return Err(TransportError::SessionFenced),
        };
        self.retire_observe_pair_under_transition(operation_id, request_digest);
        Ok(ObserveDeferDisposition::Deferred(Box::new(routed)))
    }
}

/// Accepts a generated campaign view only as part of the exact admitted
/// `eliot.packet` result that produced it. This binding is checked before the
/// result and view are atomically retained by ORS.
fn validate_campaign_view_result(
    stored: &HostRequestRecord,
    envelope: Option<&HostRequestEnvelope>,
    response: &serde_json::Value,
) -> Result<(), TransportError> {
    let Some(value) = response.get("campaign_learning_state_view") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    if stored.capability_ref.as_str() != "eliot.packet" {
        return Err(TransportError::SessionFenced);
    }
    let envelope = envelope.ok_or(TransportError::SessionFenced)?;
    let publication: CampaignLearningStateViewPublication =
        serde_json::from_value(value.clone()).map_err(|_| TransportError::SessionFenced)?;
    publication
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if envelope.identity.task_id.as_deref() != Some(publication.task_id.as_str())
        || envelope.identity.work_scope_id.as_deref() != Some(publication.scope_id.as_str())
        || envelope.state_fence != publication.state_fence
        || stored.task_ref.as_ref().map(OpaqueLabel::as_str) != Some(publication.task_id.as_str())
        || stored.scope_ref.as_ref().map(OpaqueLabel::as_str) != Some(publication.scope_id.as_str())
        || sha256_json(&publication.state_fence).map_err(|_| TransportError::SessionFenced)?
            != stored.fence_digest
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

/// Builds the Kernel-observed bridge process binding from retained state.
///
/// Every field comes from the current admission descriptor or the retained
/// transport admission receipt for the presenting connection; no
/// caller-supplied process identity is accepted. A receipt retained from a
/// superseded generation disagrees with the current descriptor, so the
/// Writer-A process-binding gate rejects it and stale generations never
/// revive through this path.
fn bridge_process_binding(
    descriptor: &AgentBridgeAdmissionDescriptor,
    receipt: &AgentBridgePeerAdmissionReceipt,
    connection_id: &str,
) -> Result<AgentBridgeProcessBinding, TransportError> {
    AgentBridgeProcessBinding {
        wire_id: AGENT_BRIDGE_PROCESS_BINDING_WIRE_ID.to_owned(),
        wire_version: AgentBridgeProcessBinding::CONTRACT_VERSION,
        module_id: descriptor.module_id.clone(),
        profile_id: descriptor.profile_id.as_str().to_owned(),
        connection_id: connection_id.to_owned(),
        descriptor_sha256: descriptor.descriptor_sha256.clone(),
        executable_sha256: descriptor.executable_sha256.clone(),
        executable_volume_serial: descriptor.executable_identity.volume_serial_number,
        executable_file_index: descriptor.executable_identity.file_index,
        bridge_generation: descriptor.generation,
        state_fence: descriptor.state_fence.clone(),
        observed_sid: receipt.observed_sid.clone(),
        observed_session_id: receipt.observed_session_id,
        observed_process_id: receipt.observed_process_id,
        observed_process_start_time_100ns: receipt.observed_process_start_time_100ns,
        observed_image_path: receipt.observed_image_path.clone(),
        binding_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| TransportError::SessionFenced)
}

/// Builds the `Requested` ORS record for one validated envelope.
///
/// Every identity is preserved opaquely: Session, task, scope, capability,
/// fence, and payload values become exact bytes or digests for replay
/// comparison and are never interpreted here.
pub(crate) fn requested_host_request_record(
    envelope: &HostRequestEnvelope,
) -> Result<HostRequestRecord, TransportError> {
    let label =
        |value: &str| OpaqueLabel::new(value.to_owned()).map_err(|_| TransportError::SessionFenced);
    let optional_label = |value: Option<&String>| value.map(|identity| label(identity)).transpose();
    Ok(HostRequestRecord {
        contract_version: ORS_CONTRACT_VERSION,
        operation_id: OperationIdentity::new(host_request_operation_id(envelope))
            .map_err(|_| TransportError::SessionFenced)?,
        kind: match envelope.kind {
            HostRequestKind::Activation => OrsHostRequestKind::Activation,
            HostRequestKind::Invocation => OrsHostRequestKind::Invocation,
            HostRequestKind::Cancellation => OrsHostRequestKind::Cancellation,
            HostRequestKind::Status => OrsHostRequestKind::Status,
            HostRequestKind::Reconciliation => OrsHostRequestKind::Reconciliation,
        },
        request_id: label(envelope.identity.request_id.as_str())?,
        idempotency_key: label(&envelope.identity.idempotency_key)?,
        cancellation_id: label(&envelope.identity.cancellation_id)?,
        parent_operation_id: optional_label(envelope.identity.parent_operation_id.as_ref())?,
        request_digest: envelope.envelope_sha256.clone(),
        payload_digest: envelope.identity.payload_sha256.clone(),
        connection_ref: label(&envelope.connection_id)?,
        session_ref: optional_label(envelope.identity.session_id.as_ref())?,
        task_ref: optional_label(envelope.identity.task_id.as_ref())?,
        scope_ref: optional_label(envelope.identity.work_scope_id.as_ref())?,
        capability_ref: label(&envelope.identity.capability)?,
        fence_digest: sha256_json(&envelope.state_fence)
            .map_err(|_| TransportError::SessionFenced)?,
        authority_epoch: envelope.state_fence.authority_epoch.clone(),
        generation: envelope.state_fence.resource_generation.value(),
        deadline_unix_ms: envelope.identity.deadline_unix_ms,
        state: HostRequestState::Requested,
        result_digest: None,
        result_response: None,
        commit_order: 0,
    })
}

/// Derives the exact ORS key of the parent operation targeted by a
/// `Cancellation`, `Status`, or `Reconciliation` envelope.
///
/// The parent operation handle deterministically carries the parent envelope
/// digest after its prefix; the digest is re-validated before any lookup so a
/// malformed reference is reported as an unknown operation.
fn parent_operation_key(
    envelope: &HostRequestEnvelope,
) -> Result<(OperationIdentity, String), TransportError> {
    let parent = envelope
        .identity
        .parent_operation_id
        .as_ref()
        .ok_or(TransportError::UnknownRequest)?;
    let digest = parent
        .strip_prefix(HOST_REQUEST_OPERATION_ID_PREFIX)
        .ok_or(TransportError::UnknownRequest)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(TransportError::UnknownRequest);
    }
    let operation =
        OperationIdentity::new(parent.clone()).map_err(|_| TransportError::UnknownRequest)?;
    Ok((operation, digest.to_owned()))
}

/// Advances one indexed operation to `Unknown` unless it already closed.
///
/// Terminal records stay under their owner's continuation rules; every store
/// error is contained because disconnect fencing must hold even when the
/// store is unavailable.
///
/// The caller drops the indexed reference after fencing, which also retires
/// any queued local-read pair: removal from the connection index IS attempt
/// invalidation, and submit requires a live claim record, so a fenced pair
/// can never complete afterwards. Claimed pairs are never exempt.
fn fence_one_host_request(
    composition: &KernelComposition,
    operation_ref: &HostRequestOperationRef,
) {
    let Ok(operation_id) = OperationIdentity::new(operation_ref.operation_id.clone()) else {
        return;
    };
    let Ok(current) = composition
        .generation_gateway
        .ors
        .load_host_request(&operation_id, &operation_ref.request_digest)
    else {
        return;
    };
    let Some(record) = current else {
        return;
    };
    if record.state.is_terminal() {
        return;
    }
    let _ = composition.generation_gateway.ors.advance_host_request(
        &operation_id,
        &operation_ref.request_digest,
        HostRequestState::Unknown,
        None,
    );
}

/// Requires a parent record to belong to the current descriptor generation
/// and authority epoch.
///
/// Operations from a superseded generation are stale, not unknown: touching
/// them through a current connection fails closed instead of reviving old
/// authority.
fn require_current_generation_parent(
    parent: &HostRequestRecord,
    descriptor: &AgentBridgeAdmissionDescriptor,
) -> Result<(), TransportError> {
    if parent.authority_epoch != descriptor.authority_epoch
        || parent.generation != descriptor.generation.value()
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

impl KernelComposition {
    /// Dispatches one typed host-request frame from the admitted bridge transport.
    ///
    /// The caller ([`crate::KernelComposition::dispatch_frame`]) has already
    /// run the closed gateway gates (generation poison, session/frame
    /// identity, daemon-session currency); those joins are re-checked here so
    /// direct callers cannot bypass them. The envelope must ride the same
    /// connection as the presenting admitted Session, and the frame
    /// correlation identity must equal the envelope request identity,
    /// mirroring the activation decode. Digest, descriptor, fence,
    /// generation, deadline, and durability joins live in the admit path
    /// ([`Self::admit_host_request_envelope`] and its kind-specific entries),
    /// which remains the single owner of ORS staging and receipts. Unknown
    /// operations and mismatched joins fence; nothing is ever retried blindly.
    pub(crate) fn dispatch_host_request_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if !matches!(
            self.service_state()
                .map_err(|_| TransportError::SessionFenced)?,
            KernelServiceState::Ready | KernelServiceState::Degraded
        ) {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let request_id = frame
            .request_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let identity = frame
            .request_identity
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&identity.request.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        let operation = payload
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if !is_host_request_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        if is_bridge_event_operation(operation) {
            // Agent-bridge event delivery rides the same admitted gateway but
            // never the host-request envelope: the event handlers below join
            // the retained Session (connection plus live fence) against the
            // presented durable/control envelope and stage into the disjoint
            // bridge-event ORS tables. A refused event is never resubmitted
            // as a host request.
            return self.dispatch_bridge_event_frame(session, frame, operation);
        }
        let envelope = host_request_envelope_from_payload(&payload)?;
        if envelope.connection_id != session.connection_id
            || frame.connection_id != session.connection_id
        {
            return Err(TransportError::SessionFenced);
        }
        if frame.request_id.as_ref() != Some(&envelope.identity.request_id) {
            return Err(TransportError::SessionFenced);
        }
        let value = match operation {
            AGENT_HOST_REQUEST_SUBMIT_OPERATION => {
                // Observe bytes ride this same entry (issue #2565): when the
                // payload carries them for the admitted `eliot.observe`
                // capability, the pure linkage gate runs before any staging,
                // and the bounded reservation helper completes admission and
                // payload handoff before the acknowledgement below.
                // Digest-only submits keep the legacy shape untouched.
                let observe_tool = payload.get("tool").cloned();
                let (receipt, record) =
                    self.admit_and_queue_observe_submit(&envelope, observe_tool.as_ref())?;
                host_request_admitted_response(&receipt, &record)
            }
            AGENT_HOST_REQUEST_CANCEL_OPERATION => {
                let (receipt, record) = self.cancel_host_request(&envelope)?;
                host_request_admitted_response(&receipt, &record)
            }
            AGENT_HOST_REQUEST_RECONCILE_OPERATION => {
                let (receipt, record) = self.reconcile_host_request(&envelope)?;
                host_request_admitted_response(&receipt, &record)
            }
            AGENT_HOST_REQUEST_REHYDRATE_OPERATION => {
                let receipt = host_request_receipt_from_payload(&payload)?;
                let record = self.rehydrate_host_request(&envelope, &receipt)?;
                host_request_rehydrated_response(&record)
            }
            AGENT_HOST_REQUEST_RESOLVE_OPERATION => {
                let query = payload
                    .get("query")
                    .cloned()
                    .ok_or(TransportError::SessionFenced)?;
                self.resolve_host_request_by_logical_key(&envelope, &query)?
            }
            AGENT_HOST_REQUEST_INVOKE_READ_OPERATION => {
                let tool = host_request_tool_from_payload(&payload)?;
                let (receipt, record) = self.invoke_read_host_request(&envelope, &tool)?;
                // The durable record carries the result pair when the
                // operation already received its bounded answer, so the
                // admitted shape is the result-bearing response: no second
                // shape, no duplicated body, no frame-ceiling risk.
                host_request_admitted_response(&receipt, &record)
            }
            _ => return Err(TransportError::SessionFenced),
        };
        let mut reply = status_frame(session, FrameKind::Response, MessageType::Result, value)?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(KernelFrameAction::Reply(reply))
    }

    /// Dispatches one admitted agent-bridge event frame (Implements #2561,
    /// I7.2/I7.23).
    ///
    /// The caller ([`Self::dispatch_host_request_frame`]) has already run the
    /// closed gateway gates (service state, peer, correlation, live-fence
    /// compatibility); those joins are re-checked here so a direct caller
    /// cannot bypass them. The frame must ride the same connection as the
    /// presenting admitted Session. Each closed entry stages into (or reads
    /// from) the disjoint bridge-event ORS tables; none touches the
    /// host-request ledger, and a refused event is never resubmitted as a
    /// host request. This entry creates no Session, grants no capability,
    /// completes no task, mints no canonical truth, and never produces a
    /// Problem or Incident decision: it returns durable phases and cursor
    /// facts only.
    pub(crate) fn dispatch_bridge_event_frame(
        &self,
        session: &Session,
        frame: &Frame,
        operation: &str,
    ) -> Result<KernelFrameAction, TransportError> {
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let request_id = frame
            .request_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let identity = frame
            .request_identity
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&identity.request.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        if frame.connection_id != session.connection_id {
            return Err(TransportError::SessionFenced);
        }
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        if payload.get("operation").and_then(serde_json::Value::as_str) != Some(operation) {
            return Err(TransportError::SessionFenced);
        }
        if !is_bridge_event_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        let value = match operation {
            AGENT_BRIDGE_EVENT_FORWARD_OPERATION => {
                let event = bridge_event_envelope_from_payload(&payload)?;
                self.admit_bridge_event_envelope(
                    session,
                    &event,
                    &identity.request.state_fence,
                    identity.deadline_unix_ms,
                )?
            }
            AGENT_BRIDGE_HOOK_FORWARD_OPERATION => {
                let hook = bridge_hook_from_payload(&payload)?;
                self.admit_bridge_hook_observation(session, &hook)?
            }
            AGENT_BRIDGE_EVENT_GAP_OPERATION => {
                let gap = bridge_gap_from_payload(&payload, &session.connection_id)?;
                self.admit_bridge_event_gap(session, &gap, &identity.request.state_fence)?
            }
            AGENT_BRIDGE_EVENT_RECONCILE_OPERATION => {
                let scope = bridge_reconcile_scope_from_payload(&payload)?;
                self.answer_bridge_event_reconcile(session, &scope, &identity.request.state_fence)?
            }
            _ => return Err(TransportError::SessionFenced),
        };
        let mut reply = status_frame(session, FrameKind::Response, MessageType::Result, value)?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(KernelFrameAction::Reply(reply))
    }

    /// Admits one durable/control event envelope for bridge-event delivery.
    ///
    /// Runs the mechanical authority, fence, generation, deadline, privacy,
    /// and durability checks in order, stages the ORS bridge-event row before
    /// answering, records the Governor-intake handoff, and returns the
    /// durable outcome. An exact replay returns the existing outcome without
    /// advancing anything; a changed binding under the same identity is an
    /// identity conflict. Durable delivery classes stage; best-effort
    /// telemetry is received without a durability claim (transport
    /// observation only).
    ///
    /// Privacy (I7.23) is decided before persistence: the disclosure
    /// decision over the canonical envelope bytes is computed through the
    /// ORS persistence owner and carried into the staged row, so denied
    /// content stages as the deterministic redacted projection plus its
    /// redaction receipt — never as verbatim raw. The handoff (I5(i)) is the
    /// persisted leg of the intake conversion the Governor/coordinator
    /// intake consumes on recovery: it binds the staged envelope digest and
    /// is later reconciled by [`Self::answer_bridge_event_reconcile`].
    fn admit_bridge_event_envelope(
        &self,
        session: &Session,
        event: &EventEnvelope,
        frame_fence: &eliot_contracts::StateFence,
        deadline_unix_ms: u64,
    ) -> Result<serde_json::Value, TransportError> {
        // Authority check against the retained Session, never caller text:
        // the event must cohere with the presenting live fence (same
        // authority epoch; producer and fence generations equal the live
        // generation). A stale or future producer generation is fenced and
        // recovers through reconcile, never by relabeling history as produced
        // by the new generation.
        if !event
            .authority_epoch
            .is_same_authority(&frame_fence.authority_epoch)
        {
            return Err(TransportError::SessionFenced);
        }
        let live_generation = frame_fence.resource_generation.value();
        if live_generation == 0
            || event.producer_generation.value() != live_generation
            || event.state_fence.resource_generation.value() != live_generation
        {
            return Err(TransportError::SessionFenced);
        }
        // Owner evidence for the append right comes from the retained
        // Session and the presenting fence only (issue #2729, item 2): a
        // new transport authentication recovers old streams through
        // reconcile, but a fresh event still requires the live producer
        // generation above — never a relabeled old one. Best-effort
        // telemetry carries no durability claim and needs no owner bind.
        let envelope_bytes = eliot_contracts::canonical_json_bytes(event)
            .map_err(|_| TransportError::SessionFenced)?;
        let envelope_sha = eliot_contracts::sha256_hex(&envelope_bytes);
        // Privacy decision precedes persistence: the ORS owner decides the
        // disclosure disposition over these exact bytes, and the stage entry
        // re-verifies the presented decision before any durable write. The
        // decision object travels into the durable stage below.
        let privacy = RedbRecoveryStore::bridge_event_privacy_decision(&envelope_bytes);
        let now = unix_ms();
        let expired = activation_deadline_expired(now, deadline_unix_ms);
        // `Ready` admits delivery; `Degraded` keeps only recovery (gap and
        // reconcile) while delivery sheds load with typed backpressure, so
        // the producer retries instead of losing the event. This mirrors the
        // host-request `Ready | Degraded` gate with per-entry recovery legs.
        let degraded = matches!(
            self.service_state()
                .map_err(|_| TransportError::SessionFenced)?,
            KernelServiceState::Degraded
        );
        match event.delivery_class {
            DeliveryClass::DurableControl | DeliveryClass::DurableObservation => {
                if degraded {
                    return Err(TransportError::Backpressure);
                }
                let evidence = bridge_owner_evidence(session, frame_fence)?;
                self.stage_bridge_event_durable(
                    session,
                    event,
                    &evidence,
                    &envelope_sha,
                    &privacy,
                    expired,
                )
            }
            DeliveryClass::BestEffortTelemetry => {
                if degraded {
                    // Best-effort loss under degradation emits the typed
                    // telemetry gap through the bridge's gap leg instead of a
                    // silent drop: the reply carries the loss with its reason.
                    return Ok(bridge_event_best_effort_response(
                        event,
                        false,
                        "kernel-degraded",
                    ));
                }
                Ok(bridge_event_best_effort_response(event, true, ""))
            }
        }
    }

    /// Stages one durable/control event with its pre-persistence privacy
    /// decision and records the Governor-intake handoff (Implements #2561,
    /// I7.23 + I5(i)).
    ///
    /// The caller ([`Self::admit_bridge_event_envelope`]) has already run the
    /// authority, fence, generation, and deadline gates and decided the
    /// disclosure disposition over the canonical envelope bytes; `privacy`
    /// carries that decision object. This entry stages the ORS row (the
    /// stage entry re-verifies the decision before any durable write),
    /// answers the determined conflict on changed bytes under a known
    /// identity, stages-then-times-out on an elapsed absolute deadline, and
    /// confirms the idempotent intake handoff before answering `DURABLE`.
    /// The pending handoff is staged atomically with the event row in the
    /// same ORS transaction (issue #2731), so the expired-submit early
    /// return below still leaves a recoverable handoff: a timeout after
    /// stage is never proof of non-acceptance, and the duplicate/reconcile
    /// recovery legs report the exact pending phase instead of a blanket
    /// safe-to-resubmit answer.
    fn stage_bridge_event_durable(
        &self,
        session: &Session,
        event: &EventEnvelope,
        evidence: &BridgeOwnerEvidence,
        envelope_sha: &str,
        privacy: &serde_json::Value,
        expired: bool,
    ) -> Result<serde_json::Value, TransportError> {
        let privacy_disposition = privacy
            .get("privacy_disposition")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        let redacted_classes = privacy
            .get("redacted_classes")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let redaction_reason = privacy
            .get("redaction_reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let staged = serde_json::json!({
            "stream_id": event.stream_id,
            "event_id": event.event_id,
            "sequence": event.sequence,
            "producer_id": event.producer_id,
            "producer_generation": event.producer_generation.value(),
            "authority_epoch": bridge_epoch_text(&event.authority_epoch),
            "envelope": serde_json::to_value(event)
                .map_err(|_| TransportError::SessionFenced)?,
            "envelope_sha256": envelope_sha,
            "staging_connection": session.connection_id,
            "privacy_disposition": privacy_disposition,
            "redacted_classes": redacted_classes,
            "redaction_reason": redaction_reason,
            "owner_principal": evidence.principal,
            "owner_authority_lineage": evidence.authority_lineage,
            "owner_connection": evidence.connection,
            "owner_launch_nonce": evidence.launch_nonce,
            "owner_session_epoch": evidence.session_epoch,
        });
        let outcome = self
            .generation_gateway
            .ors
            .stage_bridge_event_checked(&staged);
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(OrsError::DuplicateConflict) => {
                // Changed bytes under a known identity are a
                // determined rejection, not an unknown outcome: answer
                // the conflict with the proven owner's cursor facts, or
                // with an indistinguishable unknown shape for a foreign
                // presenter, so the durable row is untouched and no
                // foreign digest or cursor leaks.
                return self.bridge_event_conflict_response(event, evidence, envelope_sha);
            }
            Err(error) => {
                return Err(match error {
                    OrsError::ProjectionLimitExceeded | OrsError::PayloadTooLarge => {
                        TransportError::Backpressure
                    }
                    _ => TransportError::SessionFenced,
                });
            }
        };
        // An elapsed absolute deadline is staged honestly, then
        // reported as a timeout instead of an admission: the durable
        // record preserves the late presentation for reconcile, while
        // the caller observes the timeout. Exact replays ignore the
        // deadline and return the stored outcome (lookup path).
        if expired && outcome.get("fresh").and_then(serde_json::Value::as_bool) == Some(true) {
            return Err(TransportError::Timeout);
        }
        let phase = outcome
            .get("phase")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if phase != BRIDGE_EVENT_PHASE_DURABLE {
            return Err(TransportError::SessionFenced);
        }
        // Handoff persist (I5(i)): the staged durable event is handed
        // toward Governor/coordinator intake under its envelope
        // digest. The handoff entry is idempotent, so a lost
        // acknowledgement replays to the existing handoff instead of
        // a second record; a handoff failure fails closed here while
        // the durable row stays staged for reconcile recovery.
        let handoff = serde_json::json!({
            "owner_namespace": outcome
                .get("owner_namespace")
                .and_then(serde_json::Value::as_str)
                .ok_or(TransportError::SessionFenced)?,
            "event_id": event.event_id,
            "sequence": event.sequence,
            "envelope_sha256": envelope_sha,
            "staging_connection": session.connection_id,
        });
        self.generation_gateway
            .ors
            .record_bridge_event_handoff_checked(&handoff)
            .map_err(|error| match error {
                OrsError::DuplicateConflict => TransportError::IdentityConflict,
                // Capacity exhaustion is typed backpressure with the
                // exhausted dimension (issue #2731, item 6): the handoff
                // table is a bounded delivery budget, never an
                // authentication failure.
                OrsError::ProjectionLimitExceeded | OrsError::PayloadTooLarge => {
                    TransportError::Backpressure
                }
                _ => TransportError::SessionFenced,
            })?;
        Ok(bridge_event_forward_response(&outcome, true))
    }

    /// Answers a same-identity content conflict with the proven owner's
    /// cursor facts and the `REJECTED`/`conflict` phase pair (issue #2729,
    /// item 4).
    ///
    /// The durable row is untouched; the reply binds the presented digest
    /// so the bridge can prove the alteration. The bridge maps this
    /// determined rejection to its typed conflict outcome — never to a
    /// guessed phase and never to a second record. A foreign or unknown
    /// presenter receives the identical shape with empty facts, so a
    /// rejected caller learns no other stream's digest or cursors.
    fn bridge_event_conflict_response(
        &self,
        event: &EventEnvelope,
        evidence: &BridgeOwnerEvidence,
        presented_sha: &str,
    ) -> Result<serde_json::Value, TransportError> {
        let query = serde_json::json!({
            "owner_authority_lineage": evidence.authority_lineage,
            "owner_principal": evidence.principal,
            "producer_id": event.producer_id,
            "stream_id": event.stream_id,
            "event_id": event.event_id,
        });
        let existing = self
            .generation_gateway
            .ors
            .load_bridge_event_conflict_view(&query)
            .map_err(|_| TransportError::SessionFenced)?;
        let (existing_sha, durable, acked) = existing
            .as_ref()
            .map(|row| {
                (
                    row.get("envelope_sha256")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    row.get("durable_cursor")
                        .and_then(serde_json::Value::as_u64),
                    row.get("acked_cursor").and_then(serde_json::Value::as_u64),
                )
            })
            .unwrap_or_default();
        Ok(serde_json::json!({ "status": "known", "value": {
            "accepted": false,
            "phase": "REJECTED",
            "disposition": "conflict",
            "stream_id": event.stream_id,
            "event_id": event.event_id,
            "sequence": event.sequence,
            "envelope_sha256": presented_sha,
            "existing_envelope_sha256": existing_sha,
            "durable_cursor": durable,
            "acked_cursor": acked,
            "fresh": false,
        } }))
    }

    /// Admits one digest-bound hook observation without a durable phase.
    ///
    /// The hook signature carries no acknowledgement, so no durability is
    /// claimed: the reply answers RECEIVED transport observation bound to the
    /// exact hook digest. The bridge journal (core `observe_host_event`) owns
    /// the diagnostic history; no ORS row is staged here.
    fn admit_bridge_hook_observation(
        &self,
        session: &Session,
        hook: &BridgeHookObservation,
    ) -> Result<serde_json::Value, TransportError> {
        if !matches!(
            self.service_state()
                .map_err(|_| TransportError::SessionFenced)?,
            KernelServiceState::Ready
        ) {
            return Err(TransportError::Backpressure);
        }
        let _ = session;
        Ok(serde_json::json!({
            "status": "known",
            "value": {
                "accepted": true,
                "received": true,
                "event_id": hook.event_id,
                "sequence": hook.sequence,
                "hook_digest": hook.digest,
            },
        }))
    }

    /// Admits one forwarded coverage gap into durable coverage without moving
    /// any cursor (issue #2729, items 4-5). Gap rows stay visible through
    /// owner-scoped reconcile; absent events are accounted for, never
    /// converted into applied events. The gap is namespaced through the
    /// presenter's admitted owner evidence: scoped gaps ride their
    /// stream's retained owner, unscoped gaps bind the reporter's own
    /// occurrence.
    fn admit_bridge_event_gap(
        &self,
        session: &Session,
        gap: &serde_json::Value,
        frame_fence: &eliot_contracts::StateFence,
    ) -> Result<serde_json::Value, TransportError> {
        if !matches!(
            self.service_state()
                .map_err(|_| TransportError::SessionFenced)?,
            KernelServiceState::Ready | KernelServiceState::Degraded
        ) {
            return Err(TransportError::SessionFenced);
        }
        let evidence = bridge_owner_evidence(session, frame_fence)?;
        let mut gap = gap.clone();
        let object = gap.as_object_mut().ok_or(TransportError::SessionFenced)?;
        object.insert(
            "owner_principal".to_owned(),
            serde_json::Value::String(evidence.principal),
        );
        object.insert(
            "owner_authority_lineage".to_owned(),
            serde_json::Value::String(evidence.authority_lineage),
        );
        object.insert(
            "owner_connection".to_owned(),
            serde_json::Value::String(evidence.connection),
        );
        object.insert(
            "owner_launch_nonce".to_owned(),
            serde_json::Value::String(evidence.launch_nonce),
        );
        object.insert(
            "owner_session_epoch".to_owned(),
            serde_json::Value::from(evidence.session_epoch),
        );
        let outcome = self
            .generation_gateway
            .ors
            .record_bridge_event_gap_checked(&gap)
            .map_err(|error| match error {
                OrsError::DuplicateConflict => TransportError::IdentityConflict,
                OrsError::ProjectionLimitExceeded => TransportError::Backpressure,
                _ => TransportError::SessionFenced,
            })?;
        let accepted = outcome
            .get("accepted")
            .and_then(serde_json::Value::as_bool)
            .ok_or(TransportError::SessionFenced)?;
        if !accepted {
            return Err(TransportError::SessionFenced);
        }
        Ok(serde_json::json!({ "status": "known", "value": outcome }))
    }

    /// Answers event-ownership/cursor reconciliation from the bridge-event
    /// tables only — never from the host-request ledger (issue #2729).
    ///
    /// The whole scope resolves before anything mutates: every consumed
    /// entry is bound to its admitted owner namespace first, then the
    /// accepted batch commits in one ORS write transaction with
    /// expected-owner/revision checks, so a mixed own/foreign batch leaves
    /// all cursors and payloads unchanged. The Kernel's existing
    /// transition serialization is held across resolution and commit, so
    /// revocation between lookup and commit cannot be ignored. The reply
    /// enumerates exactly the presenter's proven scope plus an explicit
    /// unproven-scope flag — never an empty successful inventory, never a
    /// foreign digest, cursor, or gap content. The reply digest binds the
    /// reconciliation key that later reconciles the Governor-intake
    /// handoffs covered by the consumed frontier under that key (I5(i));
    /// handoff reconcile is a separate idempotent step with no cross-store
    /// atomicity claim. A lost answer replays safely: acknowledgement
    /// advances monotonically and handoff reconcile converges.
    ///
    /// Reconcile-key preimage contract (issue #2731, I5.27 identity over
    /// canonical bytes): `reconcile_key` is the SHA-256 hex of the canonical
    /// JSON bytes of the reconciliation object BEFORE attaching
    /// `reconcile_key`, `handoffs_reconciled`, and `handoff_maintenance`,
    /// so the preimage is the answer minus exactly those three post-key
    /// legs. The consumer strips all three before re-hashing; covering any
    /// post-key leg in the digest refuses every answer and discards the
    /// maintenance receipt while its store-side effect already committed.
    ///
    /// Issue #2731 runs the bounded handoff maintenance after the reconcile
    /// loop on the same recovery path: per presented namespace it retires
    /// terminal handoffs (freeing the lifetime charge while #2730 replay
    /// identity stands) and repairs retained events missing their handoff
    /// under the original identity, each with a finite budget and a
    /// continuation the next legitimate recovery entry resumes.
    fn answer_bridge_event_reconcile(
        &self,
        session: &Session,
        scope: &BridgeReconcileScope,
        frame_fence: &eliot_contracts::StateFence,
    ) -> Result<serde_json::Value, TransportError> {
        // Existing transition serialization first: the read guard is held
        // across owner resolution and the batch commit below, so bridge
        // profile fencing (the revocation path) cannot interleave
        // unnoticed. No caller above holds this guard; the service-state
        // read inside takes only its own short-lived lock.
        let _transition = self.agent_bridge_transition_read()?;
        if !matches!(
            self.service_state()
                .map_err(|_| TransportError::SessionFenced)?,
            KernelServiceState::Ready | KernelServiceState::Degraded
        ) {
            return Err(TransportError::SessionFenced);
        }
        let live_generation = frame_fence.resource_generation.value();
        if live_generation == 0 {
            return Err(TransportError::SessionFenced);
        }
        let evidence = bridge_owner_evidence(session, frame_fence)?;
        // Contradictory duplicates fail the whole scope before any store
        // mutation; the batch re-validates the same rule for its callers.
        reject_contradictory_consumed(&scope.consumed)?;
        let presenter = serde_json::json!({
            "owner_authority_lineage": evidence.authority_lineage,
            "owner_principal": evidence.principal,
        });
        // Resolve every consumed entry to its admitted namespace before
        // mutating: any foreign, stale, or ambiguous item rejects the
        // whole scope with nothing changed.
        let mut batch_items: Vec<serde_json::Value> = Vec::with_capacity(scope.consumed.len());
        let mut batch_namespaces: Vec<(String, String, u64, u64, u64)> =
            Vec::with_capacity(scope.consumed.len());
        for (stream_id, sequence) in &scope.consumed {
            let item = self
                .generation_gateway
                .ors
                .resolve_bridge_ack_item(&presenter, stream_id)
                .map_err(|_| TransportError::SessionFenced)?;
            let namespace = item
                .get("namespace")
                .and_then(serde_json::Value::as_str)
                .ok_or(TransportError::SessionFenced)?;
            let revision = item
                .get("revision")
                .and_then(serde_json::Value::as_u64)
                .ok_or(TransportError::SessionFenced)?;
            let incarnation = item
                .get("incarnation")
                .and_then(serde_json::Value::as_u64)
                .ok_or(TransportError::SessionFenced)?;
            batch_namespaces.push((
                namespace.to_owned(),
                stream_id.clone(),
                *sequence,
                revision,
                incarnation,
            ));
            batch_items.push(serde_json::json!({
                "namespace": namespace,
                "expected_revision": revision,
                "expected_incarnation": incarnation,
                "sequence": sequence,
                "owner_authority_lineage": evidence.authority_lineage,
                "owner_principal": evidence.principal,
            }));
        }
        // One ORS write transaction applies the accepted batch; validation
        // precedes commit inside it, so any failure leaves every cursor
        // and payload untouched. A commit failure surfaces as a transport
        // failure — an unknown/replayable result, never evidence that
        // nothing happened.
        if !batch_items.is_empty() {
            self.generation_gateway
                .ors
                .acknowledge_bridge_event_batch(&serde_json::json!({ "items": batch_items }))
                .map_err(|error| match error {
                    OrsError::ProjectionLimitExceeded | OrsError::PayloadTooLarge => {
                        TransportError::Backpressure
                    }
                    _ => TransportError::SessionFenced,
                })?;
        }
        let mut reconciliation = self
            .generation_gateway
            .ors
            .reconcile_bridge_events_for_owner(&presenter, live_generation)
            .map_err(|_| TransportError::SessionFenced)?;
        reconciliation["connection_id"] = serde_json::Value::String(session.connection_id.clone());
        reconciliation["live_generation"] = serde_json::Value::from(live_generation);
        let key_bytes = eliot_contracts::canonical_json_bytes(&reconciliation)
            .map_err(|_| TransportError::SessionFenced)?;
        let reconcile_key = eliot_contracts::sha256_hex(&key_bytes);
        reconciliation["reconcile_key"] = serde_json::Value::String(reconcile_key.clone());
        let mut handoffs_reconciled = 0_u64;
        for (namespace, _, sequence, _, _) in &batch_namespaces {
            let marked = self
                .generation_gateway
                .ors
                .reconcile_bridge_event_handoffs_checked(namespace, *sequence, &reconcile_key)
                .map_err(|_| TransportError::SessionFenced)?;
            handoffs_reconciled += marked
                .get("reconciled")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
        }
        reconciliation["handoffs_reconciled"] = serde_json::Value::from(handoffs_reconciled);
        let handoff_maintenance = self.maintain_bridge_event_handoffs(&batch_namespaces)?;
        reconciliation["handoff_maintenance"] = serde_json::Value::Array(handoff_maintenance);
        Ok(serde_json::json!({ "status": "known", "value": {
            "accepted": true,
            "reconciliation": reconciliation,
        } }))
    }

    /// Runs the bounded handoff maintenance for one reconciled scope on the
    /// existing owner recovery path (issue #2731, items 3 and 5): per
    /// presented namespace it retires terminal handoffs first so eligible
    /// rows free their charge before the repair slice accounts its bounded
    /// inserts, then restores missing handoffs for retained events under
    /// their original identities. Both steps are idempotent with finite
    /// per-call budgets and continuations, so a lost answer replays safely
    /// and successive legitimate recovery entries converge. Maintenance
    /// pressure answers typed backpressure (never a cursor reset or a
    /// declaration that missing evidence is complete); any other
    /// maintenance failure fails the frame closed. The per-namespace result
    /// rides the reconcile answer as the `handoff_maintenance` post-key leg,
    /// excluded from the `reconcile_key` preimage by construction (see the
    /// preimage contract on [`Self::answer_bridge_event_reconcile`]).
    fn maintain_bridge_event_handoffs(
        &self,
        batch_namespaces: &[(String, String, u64, u64, u64)],
    ) -> Result<Vec<serde_json::Value>, TransportError> {
        let mut handoff_maintenance: Vec<serde_json::Value> =
            Vec::with_capacity(batch_namespaces.len());
        for (namespace, stream_id, _, revision, incarnation) in batch_namespaces {
            let maintenance_request = serde_json::json!({
                "namespace": namespace,
                "expected_revision": revision,
                "expected_incarnation": incarnation,
            });
            let retired = self
                .generation_gateway
                .ors
                .retire_bridge_event_handoffs_checked(&maintenance_request)
                .map_err(|error| match error {
                    OrsError::ProjectionLimitExceeded | OrsError::PayloadTooLarge => {
                        TransportError::Backpressure
                    }
                    _ => TransportError::SessionFenced,
                })?;
            let repaired = self
                .generation_gateway
                .ors
                .repair_bridge_event_handoffs_checked(&maintenance_request)
                .map_err(|error| match error {
                    OrsError::ProjectionLimitExceeded | OrsError::PayloadTooLarge => {
                        TransportError::Backpressure
                    }
                    _ => TransportError::SessionFenced,
                })?;
            handoff_maintenance.push(serde_json::json!({
                "stream_id": stream_id,
                "retired": retired.get("retired").and_then(serde_json::Value::as_u64).unwrap_or(0),
                "retirement_continuation": retired
                    .get("retirement_continuation")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                "repaired": repaired.get("repaired").and_then(serde_json::Value::as_u64).unwrap_or(0),
                "repair_continuation": repaired
                    .get("repair_continuation")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            }));
        }
        Ok(handoff_maintenance)
    }
    /// The caller ([`crate::KernelComposition::dispatch_frame`]) has already run
    /// the closed gateway gates; those joins are re-checked here so a direct
    /// caller cannot bypass them. The frame must ride the same connection as
    /// the presenting admitted Session, and the correlation identity must be
    /// present. The typed batch decode, the mechanical envelope validation, and
    /// the durable named intent mutation live in
    /// [`Self::admit_watchdog_intent_batch`]. This entry creates no Session,
    /// grants no capability beyond the one observation submission the batch
    /// already presents, mints no canonical truth, and never produces a Problem
    /// or Incident decision.
    pub(crate) fn dispatch_watchdog_intent_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?
            != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let request_id = frame
            .request_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let identity = frame
            .request_identity
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&identity.request.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        if frame.connection_id != session.connection_id {
            return Err(TransportError::SessionFenced);
        }
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        let operation = payload
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if !is_watchdog_intent_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        // The typed batch is bounded before decode: an oversized frame never
        // reaches the parser or any durable write.
        let batch_bytes = payload
            .get("intent_batch")
            .ok_or(TransportError::SessionFenced)
            .and_then(|batch| {
                eliot_contracts::canonical_json_bytes(batch)
                    .map_err(|_| TransportError::SessionFenced)
            })?;
        if batch_bytes.len() > MAX_WATCHDOG_INTENT_BATCH_BYTES {
            return Err(TransportError::SessionFenced);
        }
        let batch = watchdog_intent_batch_from_payload(&payload)?;
        let projections = self.admit_watchdog_intent_batch(session, &batch)?;
        let value = watchdog_intent_batch_response(&projections, &batch.sink_id);
        let mut reply = status_frame(session, FrameKind::Response, MessageType::Result, value)?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(KernelFrameAction::Reply(reply))
    }

    /// Returns a snapshot of the retained admitted bridge transport Session.
    ///
    /// The front-door post-activation loop drives every host-request frame
    /// through [`Self::dispatch_frame`] against this retained Session, so
    /// durable Session continuity comes from the Kernel-owned admission —
    /// never from process identity or caller-supplied bindings. Connections
    /// without a completed activation and a retained Session (including typed
    /// activation denials) fail closed here; the caller revokes them without
    /// serving further frames.
    pub fn host_request_bridge_session(
        &self,
        connection_id: &str,
    ) -> Result<Session, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        let connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let state = connections
            .get(connection_id)
            .ok_or(TransportError::SessionFenced)?;
        if !state.activation_completed {
            return Err(TransportError::SessionFenced);
        }
        state.session.clone().ok_or(TransportError::SessionFenced)
    }
}

/// Opaque durable-operation prefix of one Watchdog intent projection.
///
/// The durable identity is the prefix plus the derived reconciliation key, so
/// the prefix itself is never a semantic decision: it names only "a pending
/// Watchdog intent awaiting Governor reconciliation".
const WATCHDOG_INTENT_OPERATION_ID_PREFIX: &str = "watchdog-intent:";

/// Exact capability the Watchdog's fenced intent route is admitted under.
///
/// The Watchdog is admitted for this one observation-submission capability and
/// nothing else. It is not a canonical-write, task, Architecture, completion, or
/// budget capability, and no other capability membership is granted by this
/// entry.
const WATCHDOG_INTENT_CAPABILITY: &str = "eliot.watchdog.intent.submit";

/// One durable pending-intent projection produced by the named Kernel mutation.
///
/// `operation_id` and `state` are the durable ORS facts; `admitted_now`
/// distinguishes a first admission from an exact replay, which is what lets the
/// caller answer the Watchdog's submit-once contract honestly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WatchdogIntentProjection {
    pub(crate) sequence: u64,
    pub(crate) idempotency_key: String,
    pub(crate) intent_kind: WatchdogIntentKind,
    pub(crate) record_digest: String,
    pub(crate) payload_digest: String,
    pub(crate) operation_id: String,
    pub(crate) state: HostRequestState,
    pub(crate) admitted_now: bool,
}

/// Decodes the exact typed Watchdog spool intent batch from a frame payload.
///
/// The payload must carry the closed operation string plus the full typed
/// batch; the batch shape, its own canonical digest, and every covered intent
/// (including the derived reconciliation key and the retained record bytes) are
/// re-validated here, so this is typed dispatch rather than generic JSON
/// routing.
pub(crate) fn watchdog_intent_batch_from_payload(
    payload: &serde_json::Value,
) -> Result<WatchdogSpoolIntentBatchPayload, TransportError> {
    let batch_value = payload
        .get("intent_batch")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let batch: WatchdogSpoolIntentBatchPayload =
        serde_json::from_value(batch_value).map_err(|_| TransportError::SessionFenced)?;
    batch
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if batch.route != WATCHDOG_SPOOL_BATCH_ROUTE {
        return Err(TransportError::SessionFenced);
    }
    Ok(batch)
}

/// Typed answer for one admitted Watchdog intent batch.
///
/// The response carries the durable projection per submitted spool record plus
/// the reconciliation key the Kernel derived, and nothing else. In particular
/// it carries no Problem/Incident state, no Current Epistemic Position, and no
/// task, Architecture, completion, or budget decision: those remain the
/// Governor's, and the durable record behind this projection is a
/// non-canonical pending intent.
pub(crate) fn watchdog_intent_batch_response(
    projections: &[WatchdogIntentProjection],
    sink_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": {
            "accepted": true,
            "sink_id": sink_id,
            "intents": projections
                .iter()
                .map(|projection| serde_json::json!({
                    "sequence": projection.sequence,
                    "idempotency_key": projection.idempotency_key,
                    "intent_kind": projection.intent_kind.as_str(),
                    "record_digest": projection.record_digest,
                    "payload_digest": projection.payload_digest,
                    "operation_id": projection.operation_id,
                    "state": projection.state,
                    "admitted_now": projection.admitted_now,
                }))
                .collect::<Vec<_>>(),
        },
        "recovery": null,
    })
}

/// Builds the durable pending-intent record for one submitted Watchdog intent.
///
/// The record is a `Reconciliation` host request: an observation-only durable
/// row keyed by the derived reconciliation key, carrying the original Watchdog
/// evidence digest and the retained record digest and nothing more. It has no
/// field in which a canonical semantic decision could be expressed, and the
/// `Reconciliation` kind forbids a fresh result body, so the canonical
/// Problem/Incident transition cannot be smuggled through this path.
///
/// The recorded `fence_digest`, `authority_epoch`, and `generation` are derived
/// from the *Watchdog's own* submitted lineage, not from the presenting Kernel
/// fence. That fence is still checked mechanically at admission, so a stale
/// submission is still fenced; keeping it out of the durable binding is what
/// lets an exactly-once replay survive an epoch rotation, because
/// `stage_host_request` compares the whole binding and a Kernel-side fence
/// change would otherwise turn a legitimate retry into an identity conflict and
/// a second projection.
fn watchdog_intent_projection_record(
    payload: &WatchdogSpoolIntentBatchPayload,
    intent: &WatchdogSpoolIntentSubmission,
    operation_id: &OperationIdentity,
) -> Result<HostRequestRecord, TransportError> {
    let label =
        |value: &str| OpaqueLabel::new(value.to_owned()).map_err(|_| TransportError::SessionFenced);
    let epoch_lineage = eliot_contracts::EpochLineageId::new(&intent.lineage_epoch_id)
        .map_err(|_| TransportError::SessionFenced)?;
    let epoch_sequence =
        std::num::NonZeroU64::new(intent.lineage_epoch).ok_or(TransportError::SessionFenced)?;
    let authority_epoch = eliot_contracts::EpochId::new(epoch_lineage, epoch_sequence)
        .map_err(|_| TransportError::SessionFenced)?;
    let resource_generation = eliot_contracts::ResourceGeneration::new(intent.lineage_generation)
        .map_err(|_| TransportError::SessionFenced)?;
    let submitted_fence = eliot_contracts::StateFence::new(authority_epoch, resource_generation);
    Ok(HostRequestRecord {
        contract_version: ORS_CONTRACT_VERSION,
        operation_id: operation_id.clone(),
        kind: OrsHostRequestKind::Reconciliation,
        // The request identity is the derived reconciliation key: one spool
        // record, one durable request identity, forever.
        request_id: label(&intent.idempotency_key)?,
        idempotency_key: label(&intent.idempotency_key)?,
        cancellation_id: label(&format!(
            "{WATCHDOG_INTENT_OPERATION_ID_PREFIX}{}:cancel",
            intent.idempotency_key
        ))?,
        parent_operation_id: None,
        request_digest: intent.record_digest.clone(),
        payload_digest: intent.payload_digest.clone(),
        connection_ref: label(&payload.sink_id)?,
        session_ref: None,
        task_ref: None,
        scope_ref: None,
        capability_ref: label(WATCHDOG_INTENT_CAPABILITY)?,
        fence_digest: sha256_json(&submitted_fence).map_err(|_| TransportError::SessionFenced)?,
        authority_epoch: submitted_fence.authority_epoch.clone(),
        generation: intent.lineage_generation,
        deadline_unix_ms: payload.expires_at_ms,
        state: HostRequestState::Requested,
        result_digest: None,
        result_response: None,
        commit_order: 0,
    })
}

/// Decodes the exact typed envelope from a host-request frame payload.
///
/// The payload carries the closed operation string plus the full typed
/// envelope; the envelope shape (including its canonical digest) is
/// re-validated here, so this is typed dispatch, not generic JSON routing.
pub(crate) fn host_request_envelope_from_payload(
    payload: &serde_json::Value,
) -> Result<HostRequestEnvelope, TransportError> {
    let envelope_value = payload
        .get("envelope")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let envelope: HostRequestEnvelope =
        serde_json::from_value(envelope_value).map_err(|_| TransportError::SessionFenced)?;
    envelope
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(envelope)
}

/// Stored phase persisted by the bridge-event stage entry. The route answers
/// `DURABLE` only on this exact persisted phase; anything else fails closed
/// instead of promoting a weaker fact.
const BRIDGE_EVENT_PHASE_DURABLE: &str = "DURABLE";

/// Kernel-derived owner evidence for one bridge-event operation (issue
/// #2729).
///
/// Built from the retained Session and the presenting fence only: the
/// principal is the platform-verified peer identity, the lineage is the
/// presenting authority lineage, and the occurrence is the admitted
/// transport session. No bridge-authored session text is accepted — the
/// frame carries none by design, and the Kernel builds the sender binding
/// itself from the retained Session. A matching Windows identity, a
/// current generation, or an earlier connection alone never satisfies
/// this evidence: the store still requires the full binding tuple.
struct BridgeOwnerEvidence {
    principal: String,
    authority_lineage: String,
    connection: String,
    launch_nonce: String,
    session_epoch: u64,
}

/// Derives the owner evidence for one bridge-event operation from the
/// retained Session and the presenting fence (issue #2729, item 2). The
/// fence already proved compatibility with the retained Session at
/// dispatch; this entry only projects the Kernel-owned facts the store
/// binds into the versioned owner namespace.
fn bridge_owner_evidence(
    session: &Session,
    fence: &eliot_contracts::StateFence,
) -> Result<BridgeOwnerEvidence, TransportError> {
    let principal = match &session.peer {
        PeerIdentity::Authenticated { user_identity, .. } => {
            if user_identity.trim().is_empty() || user_identity.chars().any(char::is_control) {
                return Err(TransportError::SessionFenced);
            }
            user_identity.clone()
        }
        PeerIdentity::Unavailable { .. } => {
            return Err(TransportError::PeerIdentityUnavailable);
        }
    };
    let authority_lineage = fence.authority_epoch.lineage_id.as_str();
    if authority_lineage.trim().is_empty() {
        return Err(TransportError::SessionFenced);
    }
    if session.connection_id.trim().is_empty()
        || session.launch_nonce.trim().is_empty()
        || session.session_epoch == 0
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(BridgeOwnerEvidence {
        principal,
        authority_lineage: authority_lineage.to_owned(),
        connection: session.connection_id.clone(),
        launch_nonce: session.launch_nonce.clone(),
        session_epoch: session.session_epoch,
    })
}

/// Rejects contradictory consumed-frontier entries before any mutation
/// (issue #2729, item 3): the same stream twice with different sequences
/// fails the whole reconcile scope, so no batch cursor moves. The store
/// batch re-validates the same rule for its own callers.
fn reject_contradictory_consumed(consumed: &[(String, u64)]) -> Result<(), TransportError> {
    for (index, (stream, sequence)) in consumed.iter().enumerate() {
        if consumed[..index]
            .iter()
            .any(|(prior_stream, prior_sequence)| {
                prior_stream == stream && prior_sequence != sequence
            })
        {
            return Err(TransportError::SessionFenced);
        }
    }
    Ok(())
}
/// Bound on consumed-frontier entries carried by one reconcile scope.
const MAX_BRIDGE_RECONCILE_CONSUMED: usize = 1024;

/// Canonical text of a lineage-aware authority epoch (`lineage:sequence`).
/// Compared exactly by the store row; never coerced to a scalar.
fn bridge_epoch_text(epoch: &eliot_contracts::EpochId) -> String {
    format!("{}:{}", epoch.lineage_id.as_str(), epoch.sequence.get())
}

/// Decodes the exact typed durable/control event envelope from a bridge-event
/// payload.
///
/// The payload must carry the closed operation string plus the full typed
/// envelope; the envelope shape, sequencing, and fence/authority coherence
/// are re-validated here, so this is typed dispatch rather than generic JSON
/// routing.
pub(crate) fn bridge_event_envelope_from_payload(
    payload: &serde_json::Value,
) -> Result<EventEnvelope, TransportError> {
    let envelope_value = payload
        .get("envelope")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let envelope: EventEnvelope =
        serde_json::from_value(envelope_value).map_err(|_| TransportError::SessionFenced)?;
    envelope
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(envelope)
}

/// One digest-bound hook observation: the hook identity plus the exact digest
/// of its canonical bytes. The Kernel binds the digest without interpreting
/// hook semantics; the typed [`HostEventEnvelope`] contract lives
/// bridge-side, where it is validated before sending.
pub(crate) struct BridgeHookObservation {
    pub(crate) event_id: String,
    pub(crate) sequence: u64,
    pub(crate) digest: String,
}

/// Decodes one digest-bound hook observation from a hook payload.
///
/// The payload carries the closed operation string, the hook JSON under
/// `hook_envelope`, and its canonical digest under `hook_digest`. The digest
/// is recomputed over the canonical bytes and must match exactly, so the
/// reply binds the immutable observation the bridge presented.
pub(crate) fn bridge_hook_from_payload(
    payload: &serde_json::Value,
) -> Result<BridgeHookObservation, TransportError> {
    let hook_value = payload
        .get("hook_envelope")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let presented = payload
        .get("hook_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    let bytes = eliot_contracts::canonical_json_bytes(&hook_value)
        .map_err(|_| TransportError::SessionFenced)?;
    let digest = eliot_contracts::sha256_hex(&bytes);
    if digest != presented {
        return Err(TransportError::SessionFenced);
    }
    let event_id = hook_value
        .get("event_id")
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.trim().is_empty() && !text.chars().any(char::is_control))
        .ok_or(TransportError::SessionFenced)?;
    let sequence = hook_value
        .get("sequence")
        .and_then(serde_json::Value::as_u64)
        .filter(|sequence| *sequence != 0)
        .ok_or(TransportError::SessionFenced)?;
    Ok(BridgeHookObservation {
        event_id: event_id.to_owned(),
        sequence,
        digest,
    })
}

/// Decodes one forwarded coverage gap into the store gap object.
///
/// The payload carries the closed operation string, the gap JSON under `gap`
/// (identity, reason, affected interval, evidence), and the optional stream
/// scope under `stream_id` (empty when the forwarding port carries no stream
/// scope; the gap then reconciles unscoped under its staging connection).
/// Interval and identity fields are validated here; cursor movement never
/// happens on this path by construction of the store entry.
pub(crate) fn bridge_gap_from_payload(
    payload: &serde_json::Value,
    staging_connection: &str,
) -> Result<serde_json::Value, TransportError> {
    let gap_value = payload
        .get("gap")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let gap_id = gap_value
        .get("gap_id")
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.trim().is_empty() && !text.chars().any(char::is_control))
        .ok_or(TransportError::SessionFenced)?;
    let reason_ref = gap_value
        .get("reason_ref")
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.trim().is_empty() && !text.chars().any(char::is_control))
        .ok_or(TransportError::SessionFenced)?;
    let interval = gap_value
        .get("affected_interval")
        .ok_or(TransportError::SessionFenced)?;
    let start = interval
        .get("start")
        .and_then(serde_json::Value::as_u64)
        .filter(|start| *start != 0)
        .ok_or(TransportError::SessionFenced)?;
    let end = interval
        .get("end")
        .and_then(serde_json::Value::as_u64)
        .filter(|end| *end != 0)
        .ok_or(TransportError::SessionFenced)?;
    if end < start {
        return Err(TransportError::SessionFenced);
    }
    let stream_id = payload
        .get("stream_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if stream_id.chars().any(char::is_control) || stream_id.contains("::") {
        return Err(TransportError::SessionFenced);
    }
    Ok(serde_json::json!({
        "gap_id": gap_id,
        "stream_id": stream_id,
        "start_sequence": start,
        "end_sequence": end,
        "reason_ref": reason_ref,
        "staging_connection": staging_connection,
    }))
}

/// Consumed-frontier scope carried by one event reconcile request: the
/// bridge-owned delivered frontier per stream. Applied monotonically at or
/// below the durable cursor before enumeration.
pub(crate) struct BridgeReconcileScope {
    pub(crate) consumed: Vec<(String, u64)>,
}

/// Decodes the reconcile scope: a bounded list of `{stream_id, sequence}`
/// consumed-frontier entries. The list may be empty (pure ownership/cursor
/// read); anything malformed fails the whole scope.
pub(crate) fn bridge_reconcile_scope_from_payload(
    payload: &serde_json::Value,
) -> Result<BridgeReconcileScope, TransportError> {
    let consumed_value = payload
        .get("consumed")
        .ok_or(TransportError::SessionFenced)?;
    let consumed_array = consumed_value
        .as_array()
        .ok_or(TransportError::SessionFenced)?;
    if consumed_array.len() > MAX_BRIDGE_RECONCILE_CONSUMED {
        return Err(TransportError::SessionFenced);
    }
    let mut consumed = Vec::with_capacity(consumed_array.len());
    for entry in consumed_array {
        let stream_id = entry
            .get("stream_id")
            .and_then(serde_json::Value::as_str)
            .filter(|text| {
                !text.trim().is_empty()
                    && !text.chars().any(char::is_control)
                    && !text.contains("::")
            })
            .ok_or(TransportError::SessionFenced)?;
        let sequence = entry
            .get("sequence")
            .and_then(serde_json::Value::as_u64)
            .filter(|sequence| *sequence != 0)
            .ok_or(TransportError::SessionFenced)?;
        consumed.push((stream_id.to_owned(), sequence));
    }
    Ok(BridgeReconcileScope { consumed })
}

/// Typed answer for one staged durable event: the store outcome plus the
/// closed `known`/`accepted` envelope the bridge joins to its sent envelope.
/// Carries the independently verifiable phase from the persistent owner.
fn bridge_event_forward_response(outcome: &serde_json::Value, accepted: bool) -> serde_json::Value {
    let mut value = outcome.clone();
    if let Some(object) = value.as_object_mut() {
        object.insert("accepted".to_owned(), serde_json::Value::Bool(accepted));
    }
    serde_json::json!({ "status": "known", "value": value })
}

/// Typed answer for one best-effort event: transport observation without a
/// durability claim. A loss carries `forwarded: false` with its exact reason
/// so the bridge emits the typed telemetry gap instead of dropping silently.
fn bridge_event_best_effort_response(
    event: &EventEnvelope,
    forwarded: bool,
    reason: &str,
) -> serde_json::Value {
    serde_json::json!({ "status": "known", "value": {
        "accepted": true,
        "forwarded": forwarded,
        "reason": reason,
        "stream_id": event.stream_id,
        "event_id": event.event_id,
        "sequence": event.sequence,
    } })
}

/// Decodes the exact canonical tool bytes from an invoke-read payload.
///
/// The payload carries the closed operation string plus the full typed
/// envelope and the opaque canonical tool JSON. Linkage (capability +
/// payload digest over the presented bytes) is enforced by the
/// [`HostRequestInvokeReadPayload`] contract, so a changed payload is
/// rejected here before any read.
pub(crate) fn host_request_tool_from_payload(
    payload: &serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let envelope = host_request_envelope_from_payload(payload)?;
    let tool = payload
        .get("tool")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope,
        tool: tool.clone(),
    }
    .validate()
    .map_err(|_| TransportError::SessionFenced)?;
    Ok(tool)
}

/// Closed local-read selectors for one admitted `eliot.query` tool.
///
/// `scope_id` is the trusted Kernel-issued scope (envelope `work_scope_id`
/// when present, else the admitted `session_id` — never an MCP argument),
/// `subject` is the exact `subject:<exact-subject>` selector (never free
/// text, never blank), `max_records` is the explicit catalogue bound, and
/// `intent_mode` is the presented `snake_case` query mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalReadSelectors {
    pub(crate) scope_id: ScopeId,
    pub(crate) subject: String,
    pub(crate) max_records: u32,
    pub(crate) intent_mode: String,
}

/// The two local-read shapes admitted by the authenticated daemon poller.
///
/// `eliot.query` is the bounded evidence query. `eliot.packet` is a distinct
/// task-bound campaign compilation request; it must be queued and claimed just
/// like a query, but it is never converted into an evidence-pack selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LocalReadAdmission {
    /// A bounded evidence query.
    Query(LocalReadSelectors),
    /// A task-bound campaign packet with its trusted scope, task, and exact
    /// task revision admitted before it can enter the queue.
    CampaignPacket {
        scope_id: ScopeId,
        task_id: String,
        task_revision: u64,
    },
}

/// Derives the closed query selectors from one linked envelope+tool pair.
///
/// This compatibility helper remains query-only: a packet is deliberately not
/// represented as a query. The production admission gate below uses
/// [`local_read_admission_from_tool`] so packets receive their own queue
/// marker instead of disappearing behind `Ok(None)`.
pub(crate) fn local_read_selectors_from_tool(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<Option<LocalReadSelectors>, TransportError> {
    let object = tool.as_object().ok_or(TransportError::SessionFenced)?;
    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    if name == "eliot.packet" {
        return Ok(None);
    }
    if name != "eliot.query" || envelope.identity.capability != name {
        return Err(TransportError::SessionFenced);
    }
    let arguments = object
        .get("arguments")
        .and_then(serde_json::Value::as_object)
        .ok_or(TransportError::SessionFenced)?;
    let intent = arguments
        .get("intent")
        .and_then(serde_json::Value::as_object)
        .ok_or(TransportError::SessionFenced)?;
    let mode = intent
        .get("mode")
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    if mode.trim().is_empty() || mode.chars().any(char::is_control) || mode == "current_position" {
        return Err(TransportError::SessionFenced);
    }
    if arguments
        .get("exact_resource_uri")
        .is_some_and(|value| !value.is_null())
    {
        return Err(TransportError::SessionFenced);
    }
    let subject = arguments
        .get("query")
        .and_then(serde_json::Value::as_str)
        .and_then(|query| query.strip_prefix("subject:"))
        .map(str::trim)
        .filter(|subject| !subject.is_empty() && !subject.chars().any(char::is_control))
        .ok_or(TransportError::SessionFenced)?;
    let scope_id = trusted_local_read_scope(envelope)?;
    Ok(Some(LocalReadSelectors {
        scope_id,
        subject: subject.to_owned(),
        max_records: EVIDENCE_PACK_MAX_RECORDS,
        intent_mode: mode.to_owned(),
    }))
}

fn trusted_local_read_scope(envelope: &HostRequestEnvelope) -> Result<ScopeId, TransportError> {
    let scope_text = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|scope| !scope.trim().is_empty())
        .or_else(|| {
            envelope
                .identity
                .session_id
                .as_deref()
                .filter(|scope| !scope.trim().is_empty())
        })
        .ok_or(TransportError::SessionFenced)?;
    ScopeId::new(scope_text).map_err(|_| TransportError::SessionFenced)
}

/// Derives the authenticated local-read admission, preserving packet as a
/// first-class admitted shape rather than an absent selector set.
pub(crate) fn local_read_admission_from_tool(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<LocalReadAdmission, TransportError> {
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|_| TransportError::SessionFenced)?;
    let name = tool
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    match name {
        "eliot.packet" => campaign_packet_admission(envelope, tool),
        "eliot.query" => local_read_selectors_from_tool(envelope, tool)
            .map_err(|_| TransportError::SessionFenced)?
            .map(LocalReadAdmission::Query)
            .ok_or(TransportError::SessionFenced),
        _ => Err(TransportError::SessionFenced),
    }
}

/// Validates one local-read admission before any store read (no IO).
pub(crate) fn check_local_read_admission(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<LocalReadAdmission, TransportError> {
    local_read_admission_from_tool(envelope, tool)
}

/// Closed local-state selectors for one admitted `eliot.state` tool.
///
/// The trusted envelope scope (work scope else session — never an MCP
/// argument) plus the exact `include` projection-field list from the
/// `StateInput` arguments. An absent `include` is the default projection
/// (authenticated discovery with no field filter); entries mirror the MCP
/// contract's `unique_non_blank` rule exactly, so a blank, control-bearing,
/// or duplicated field fails closed here rather than travelling to the
/// Governor state owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalStateSelectors {
    pub(crate) scope_id: ScopeId,
    pub(crate) include: Vec<String>,
}

/// Derives the closed local-state selectors from one linked envelope+tool pair.
///
/// Returns the real selectors for `eliot.state`: the pair rides the shared
/// admitted-pair carrier (queued for the outbound-only eliotd poller by
/// [`KernelComposition::invoke_read_host_request`]) instead of hitting the
/// query-only stub. Fails closed as `SessionFenced` for any other tool name,
/// for a capability mismatch, for a non-object `arguments`, for a present
/// `include` that is not an array of unique non-blank control-free field
/// names, and for a missing or blank trusted scope. Mirrors the MCP
/// `StateInput` contract field-for-field without taking an MCP edge; linkage
/// (capability + payload digest) must already be proven by the caller through
/// [`HostRequestInvokeReadPayload`]. Pure: deriving selectors performs no
/// store IO.
pub(crate) fn local_state_selectors_from_tool(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<LocalStateSelectors, TransportError> {
    let object = tool.as_object().ok_or(TransportError::SessionFenced)?;
    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    if name != "eliot.state" || envelope.identity.capability != name {
        return Err(TransportError::SessionFenced);
    }
    let arguments = object
        .get("arguments")
        .and_then(serde_json::Value::as_object)
        .ok_or(TransportError::SessionFenced)?;
    let include = match arguments.get("include") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(items)) => {
            let mut seen = std::collections::BTreeSet::new();
            let mut include = Vec::with_capacity(items.len());
            for item in items {
                let field = item
                    .as_str()
                    .filter(|field| {
                        !field.trim().is_empty() && !field.chars().any(char::is_control)
                    })
                    .ok_or(TransportError::SessionFenced)?;
                if !seen.insert(field) {
                    return Err(TransportError::SessionFenced);
                }
                include.push(field.to_owned());
            }
            include
        }
        Some(_) => return Err(TransportError::SessionFenced),
    };
    let scope_text = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|scope| !scope.trim().is_empty())
        .or_else(|| {
            envelope
                .identity
                .session_id
                .as_deref()
                .filter(|scope| !scope.trim().is_empty())
        })
        .ok_or(TransportError::SessionFenced)?;
    let scope_id = ScopeId::new(scope_text).map_err(|_| TransportError::SessionFenced)?;
    Ok(LocalStateSelectors { scope_id, include })
}

/// Validates one local-state admission before any store read (no IO).
///
/// Runs the exact invoke-read linkage gate ([`HostRequestInvokeReadPayload`])
/// plus the closed state-selector derivation, so a changed payload digest, a
/// forged descriptor or capability, or a malformed `include` list is rejected
/// before the caller performs any Gateway IO or queues the pair for the
/// eliotd poller. Pure: validation performs no IO by construction, which is
/// the rejection-before-reading proof.
pub(crate) fn check_local_state_admission(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<LocalStateSelectors, TransportError> {
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|_| TransportError::SessionFenced)?;
    local_state_selectors_from_tool(envelope, tool)
}

/// Serves an exact replay of a resulted operation without re-dispatch (no IO).
///
/// Returns the admitted response when the durable record already carries both
/// halves of the digest-bound result pair (validated through
/// [`HostRequestResultBody`]); `None` for live or half-present rows, which
/// take the fresh-answer leg instead of serving a partial answer. A forged
/// pair fails closed instead of serving. Pure: readback performs no dispatch
/// and no store IO by construction.
pub(crate) fn local_read_replay_response(
    receipt: &HostRequestAdmissionReceipt,
    record: &HostRequestRecord,
    envelope: &HostRequestEnvelope,
) -> Result<Option<serde_json::Value>, TransportError> {
    let (Some(digest), Some(body)) = (&record.result_digest, &record.result_response) else {
        return Ok(None);
    };
    HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: receipt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: digest.clone(),
        response: body.clone(),
        // Replay readback only: stored rows predate attempt ownership.
        attempt: None,
    }
    .validate()
    .map_err(|_| TransportError::SessionFenced)?;
    Ok(Some(host_request_admitted_response(receipt, record)))
}

/// Decodes the exact typed admission receipt from a rehydrate payload.
///
/// The receipt is re-validated against the presenting envelope by
/// [`KernelComposition::rehydrate_host_request`]; it is never authority here.
pub(crate) fn host_request_receipt_from_payload(
    payload: &serde_json::Value,
) -> Result<HostRequestAdmissionReceipt, TransportError> {
    let receipt_value = payload
        .get("receipt")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let receipt: HostRequestAdmissionReceipt =
        serde_json::from_value(receipt_value).map_err(|_| TransportError::SessionFenced)?;
    receipt
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(receipt)
}

/// Typed acknowledgement for an admitted host-request envelope: the exact
/// Kernel-issued admission receipt plus the durable ORS record staged before
/// acknowledgement. The `known`/`accepted` shape reuses the daemon accepted
/// response vocabulary; no new status string is introduced here.
pub(crate) fn host_request_admitted_response(
    receipt: &HostRequestAdmissionReceipt,
    record: &HostRequestRecord,
) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": {
            "accepted": true,
            "operation_id": receipt.operation_id,
            "receipt": receipt,
            "record": record,
        },
        "recovery": null,
    })
}

/// Typed answer for a rehydrated host request, served from the durable ORS
/// record without advancing lifecycle state. No new receipt is issued.
pub(crate) fn host_request_rehydrated_response(record: &HostRequestRecord) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": {
            "accepted": true,
            "operation_id": record.operation_id.as_str(),
            "record": record,
        },
        "recovery": null,
    })
}

/// Typed answer for an owner-resolved host request (issue #2571).
///
/// The rehydrated shape — the original handle plus the full durable record
/// with its original digest — with the queried logical key echoed beside it,
/// so the bridge can verify the returned commitment before adopting the
/// handle, state, or result. No new receipt is issued and no state advances.
pub(crate) fn host_request_resolved_response(
    record: &HostRequestRecord,
    logical_key: Option<&str>,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "accepted": true,
        "operation_id": record.operation_id.as_str(),
        "record": record,
    });
    if let Some(key) = logical_key {
        value["logical_key"] = serde_json::Value::String(key.to_owned());
    }
    serde_json::json!({
        "status": "known",
        "value": value,
        "recovery": null,
    })
}

/// Typed answer when the resolve entry proves absence or conflict
/// (issue #2571).
///
/// `accepted:false` with the closed `resolve` disposition (`absent`: no
/// operation was ever staged under this key; `conflict`: the key is bound
/// to a different commitment). The queried logical key is echoed when the
/// query carried one; the handle form echoes nothing, so denial stays
/// indistinguishable from absence.
pub(crate) fn host_request_resolve_unresolved_response(
    disposition: &str,
    logical_key: Option<&str>,
    operation_handle: Option<&str>,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "accepted": false,
        "resolve": disposition,
    });
    if let Some(key) = logical_key {
        value["logical_key"] = serde_json::Value::String(key.to_owned());
    }
    if let Some(handle) = operation_handle {
        value["operation_handle"] = serde_json::Value::String(handle.to_owned());
    }
    serde_json::json!({
        "status": "known",
        "value": value,
        "recovery": null,
    })
}

/// Extracts validated non-blank resolve selector text.
///
/// Blank or control-bearing selectors fail closed: a confused selector must
/// never address another request's history.
fn resolve_text_field(
    query: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<String, TransportError> {
    let text = query
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    if text.trim().is_empty() || text.chars().any(char::is_control) {
        return Err(TransportError::SessionFenced);
    }
    Ok(text.to_owned())
}

/// Extracts one validated lowercase SHA-256 resolve digest.
///
/// Keys, payload commitments, and handle digests are fixed-size digests;
/// anything else fails closed before any store lookup.
fn resolve_digest_field(
    query: &serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<String, TransportError> {
    let digest = resolve_text_field(query, field)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(digest)
}

/// Splits one exact operation handle into its ORS key.
///
/// The handle deterministically carries the admitted envelope digest after
/// the prefix; the digest is re-validated before any lookup so a malformed
/// reference answers absent rather than fencing.
fn resolve_handle_key(handle: &str) -> Result<(OperationIdentity, String), TransportError> {
    let digest = handle
        .strip_prefix(HOST_REQUEST_OPERATION_ID_PREFIX)
        .ok_or(TransportError::SessionFenced)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(TransportError::SessionFenced);
    }
    let operation =
        OperationIdentity::new(handle.to_owned()).map_err(|_| TransportError::SessionFenced)?;
    Ok((operation, digest.to_owned()))
}

/// Closed EBP route identity for one Watchdog spool intent batch.
///
/// The route string is owned once by the protocol crate
/// ([`WATCHDOG_SPOOL_BATCH_ROUTE`]) and re-exported here, so the Kernel gate
/// and the Watchdog submission cannot drift into two route vocabularies.
pub use eliot_protocol::WATCHDOG_SPOOL_BATCH_ROUTE;

/// Closed frame operation carrying one Watchdog spool intent batch through the
/// front-door gateway.
///
/// It joins the same admitted host-request list as the other closed entries:
/// the operation string only selects this entry, and the payload must still
/// present the exact typed [`WatchdogSpoolIntentBatchPayload`] for validation.
pub(crate) const WATCHDOG_INTENT_SUBMIT_OPERATION: &str = "watchdog_intent_submit";

/// Bounded frame size of one Watchdog spool intent batch.
///
/// One batch carries at most
/// `eliot_protocol::MAX_WATCHDOG_SPOOL_INTENT_SUBMISSIONS` submissions, each
/// with at most `eliot_protocol::MAX_WATCHDOG_INTENT_EVIDENCE_REFS` evidence
/// references plus its retained record. The ceiling keeps the whole batch under
/// the transport frame limit without depending on the caller's declaration.
const MAX_WATCHDOG_INTENT_BATCH_BYTES: usize = 512 * 1024;

/// Validates one Watchdog spool batch envelope mechanically.
///
/// Checks process/session binding (presenting connection equals the retained
/// session connection), generation/epoch agreement against the admitted
/// fence, route identity, predecessor binding (`first == predecessor + 1`,
/// or the explicit empty-batch shape), range containment
/// (`last <= high-water`), and freshness (`created < expires`, `now <
/// expires`). There is no semantic interpretation and no canonical write:
/// payload digests, coverage, and admission stay with the Watchdog owner and
/// the Governor canonical path.
///
/// Error mapping mirrors [`KernelComposition::admit_host_request_envelope`]:
/// shape, digest, fence, descriptor, and session failures fail closed as
/// `SessionFenced`; a changed predecessor binding under the same identity is
/// `IdentityConflict`; an elapsed acknowledgement deadline is `Timeout`. No
/// error prose drives routing.
#[allow(
    clippy::too_many_arguments,
    reason = "the mechanical envelope joins stay explicit so each fence is visible at the call site"
)]
pub(crate) fn validate_watchdog_spool_batch_envelope(
    predecessor_acknowledged: u64,
    first_sequence: u64,
    last_sequence: u64,
    high_water_sequence: u64,
    watchdog_generation: u64,
    watchdog_epoch: u64,
    installation_id: &str,
    sink_id: &str,
    route: &str,
    fence_generation: u64,
    fence_epoch_sequence: u64,
    session_connection_id: &str,
    expected_connection_id: &str,
    created_at_ms: u64,
    expires_at_ms: u64,
    now_ms: u64,
    is_empty_batch: bool,
    item_count: usize,
    byte_size: u64,
) -> Result<(), TransportError> {
    if installation_id.is_empty() || sink_id.is_empty() {
        return Err(TransportError::SessionFenced);
    }
    if route != WATCHDOG_SPOOL_BATCH_ROUTE {
        return Err(TransportError::SessionFenced);
    }
    if watchdog_generation == 0 || watchdog_generation != fence_generation {
        return Err(TransportError::SessionFenced);
    }
    if watchdog_epoch != fence_epoch_sequence {
        return Err(TransportError::SessionFenced);
    }
    if session_connection_id.is_empty()
        || expected_connection_id.is_empty()
        || session_connection_id != expected_connection_id
    {
        return Err(TransportError::SessionFenced);
    }
    if created_at_ms >= expires_at_ms {
        return Err(TransportError::SessionFenced);
    }
    if now_ms >= expires_at_ms {
        return Err(TransportError::Timeout);
    }
    if is_empty_batch {
        if item_count != 0 || byte_size != 0 {
            return Err(TransportError::SessionFenced);
        }
        if predecessor_acknowledged != high_water_sequence {
            return Err(TransportError::IdentityConflict);
        }
        let expected_first = high_water_sequence
            .checked_add(1)
            .ok_or(TransportError::SessionFenced)?;
        if first_sequence != expected_first || last_sequence != high_water_sequence {
            return Err(TransportError::SessionFenced);
        }
        return Ok(());
    }
    if item_count == 0 || byte_size == 0 {
        return Err(TransportError::SessionFenced);
    }
    let expected_first = predecessor_acknowledged
        .checked_add(1)
        .ok_or(TransportError::SessionFenced)?;
    if first_sequence != expected_first {
        return Err(TransportError::IdentityConflict);
    }
    if last_sequence < first_sequence || last_sequence > high_water_sequence {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

#[cfg(test)]
mod watchdog_spool_batch_tests {
    use super::*;

    #[test]
    fn rejects_stale_epoch() {
        assert!(
            validate_watchdog_spool_batch_envelope(
                4,
                5,
                6,
                6,
                7,
                3,
                "installation-test",
                "sink-test",
                WATCHDOG_SPOOL_BATCH_ROUTE,
                7,
                3,
                "connection-1",
                "connection-1",
                1_000,
                2_000,
                1_500,
                false,
                2,
                128,
            )
            .is_ok(),
            "the mechanically bound envelope must validate"
        );
        let stale = validate_watchdog_spool_batch_envelope(
            4,
            5,
            6,
            6,
            7,
            4,
            "installation-test",
            "sink-test",
            WATCHDOG_SPOOL_BATCH_ROUTE,
            7,
            3,
            "connection-1",
            "connection-1",
            1_000,
            2_000,
            1_500,
            false,
            2,
            128,
        );
        assert_eq!(stale, Err(TransportError::SessionFenced));
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup"
)]
mod invoke_read_tool_tests {
    use super::*;
    use eliot_protocol::{HOST_REQUEST_WIRE_ID, HostRequestIdentity};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn tool_digest(tool: &serde_json::Value) -> String {
        let bytes = eliot_contracts::canonical_json_bytes(tool).expect("tool must canonicalize");
        eliot_contracts::sha256_hex(&bytes)
    }

    fn test_envelope(capability: &str, payload_sha256: &str) -> HostRequestEnvelope {
        use std::num::NonZeroU64;
        let lineage = eliot_contracts::EpochLineageId::new(TEST_LINEAGE).expect("test lineage");
        let epoch = eliot_contracts::EpochId::new(lineage, NonZeroU64::new(3).expect("nonzero"))
            .expect("test epoch");
        let fence = eliot_contracts::StateFence::new(
            epoch,
            eliot_contracts::ResourceGeneration::new(7).expect("nonzero generation"),
        );
        HostRequestEnvelope {
            wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: HostRequestEnvelope::CONTRACT_VERSION,
            kind: HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: HostRequestIdentity {
                request_id: eliot_contracts::RequestId::new("host-request-1")
                    .expect("valid request id"),
                idempotency_key: "host-request-1:invoke".to_owned(),
                cancellation_id: "host-request-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: capability.to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
                payload_sha256: payload_sha256.to_owned(),
            },
            state_fence: fence,
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("envelope must digest")
    }

    fn query_tool() -> serde_json::Value {
        serde_json::json!({"name":"eliot.query","arguments":{
            "intent":{
                "mode":"verification",
                "time_scope":"session-window",
                "branch_environment_scope":"branch",
                "freshness_policy":"exact-fence",
                "required_assurance":"evidence-provenance"
            },
            "query":"subject:evidence-alpha",
            "exact_resource_uri": null
        }})
    }

    #[test]
    fn invoke_read_rejects_changed_payload_before_reading() {
        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &tool_digest(&tool));
        let payload = serde_json::json!({"operation": AGENT_HOST_REQUEST_INVOKE_READ_OPERATION, "envelope": envelope, "tool": tool});
        let decoded =
            host_request_tool_from_payload(&payload).expect("admitted tool bytes must decode");
        assert_eq!(decoded, tool);

        // A changed payload under the same envelope digest is rejected before
        // any read: the digest no longer binds the presented bytes.
        let mut changed = tool.clone();
        changed["arguments"]["query"] = serde_json::json!("subject:forged-subject");
        let forged = serde_json::json!({"operation": AGENT_HOST_REQUEST_INVOKE_READ_OPERATION, "envelope": envelope, "tool": changed});
        assert_eq!(
            host_request_tool_from_payload(&forged),
            Err(TransportError::SessionFenced),
            "changed payload digest must be rejected before reading"
        );

        // A tool bound to another capability is rejected the same way.
        let other_envelope = test_envelope("eliot.state", &tool_digest(&tool));
        let mismatched = serde_json::json!({"operation": AGENT_HOST_REQUEST_INVOKE_READ_OPERATION, "envelope": other_envelope, "tool": tool});
        assert_eq!(
            host_request_tool_from_payload(&mismatched),
            Err(TransportError::SessionFenced),
            "capability mismatch must be rejected before reading"
        );

        // A missing tool carries no linkage proof at all.
        let missing = serde_json::json!({"operation": AGENT_HOST_REQUEST_INVOKE_READ_OPERATION, "envelope": envelope});
        assert_eq!(
            host_request_tool_from_payload(&missing),
            Err(TransportError::SessionFenced),
            "missing tool bytes must be rejected before reading"
        );
    }

    fn packet_tool() -> serde_json::Value {
        serde_json::json!({"name":"eliot.packet","arguments":{
            "packet_ref": null,
            "material_refs": []
        }})
    }

    #[test]
    fn local_read_selectors_serve_exact_triple_for_captured_subject() {
        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &tool_digest(&tool));
        let selectors = local_read_selectors_from_tool(&envelope, &tool)
            .expect("admitted query must yield selectors")
            .expect("eliot.query is a local read");
        assert_eq!(selectors.subject, "evidence-alpha");
        assert_eq!(selectors.scope_id.as_str(), "kernel-session-1");
        assert_eq!(selectors.max_records, 32);
        assert_eq!(selectors.intent_mode, "verification");
    }

    #[test]
    fn local_read_packet_is_a_distinct_queue_shape() {
        let tool = packet_tool();
        let envelope = test_envelope("eliot.packet", &tool_digest(&tool));
        assert_eq!(
            local_read_selectors_from_tool(&envelope, &tool)
                .expect("packet must not fail selector derivation"),
            None,
            "packet is not represented as an evidence-query selector"
        );
        assert!(matches!(
            check_local_read_admission(&envelope, &tool).expect("packet linkage must validate"),
            LocalReadAdmission::CampaignPacket { .. }
        ));
    }

    #[test]
    fn local_read_rejects_non_exact_selectors_before_reading() {
        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &tool_digest(&tool));

        // Free-text query is never an exact selector.
        let mut free_text = tool.clone();
        free_text["arguments"]["query"] = serde_json::json!("evidence alpha");
        assert_eq!(
            local_read_selectors_from_tool(&envelope, &free_text),
            Err(TransportError::SessionFenced),
            "free-text query must be rejected before reading"
        );

        // CurrentPosition intent never admits GetEvidencePack.
        let mut position = tool.clone();
        position["arguments"]["intent"]["mode"] = serde_json::json!("current_position");
        assert_eq!(
            local_read_selectors_from_tool(&envelope, &position),
            Err(TransportError::SessionFenced),
            "position intent must be rejected before reading"
        );

        // Exact resource expansion uses the resource path, not a query.
        let mut with_uri = tool.clone();
        with_uri["arguments"]["exact_resource_uri"] =
            serde_json::json!("eliot://resource/evidence-1");
        assert_eq!(
            local_read_selectors_from_tool(&envelope, &with_uri),
            Err(TransportError::SessionFenced),
            "exact resource URI must be rejected before reading"
        );

        // A blank subject proves nothing.
        let mut blank = tool.clone();
        blank["arguments"]["query"] = serde_json::json!("subject:   ");
        assert_eq!(
            local_read_selectors_from_tool(&envelope, &blank),
            Err(TransportError::SessionFenced),
            "blank subject must be rejected before reading"
        );

        // A foreign tool name is never the admitted operation.
        let mut foreign = tool.clone();
        foreign["name"] = serde_json::json!("eliot.state");
        assert_eq!(
            local_read_selectors_from_tool(&envelope, &foreign),
            Err(TransportError::SessionFenced),
            "foreign tool name must be rejected before reading"
        );

        // No trusted scope, no read: neither work scope nor session is bound.
        let mut noscope = test_envelope("eliot.query", &tool_digest(&tool));
        noscope.identity.work_scope_id = None;
        noscope.identity.session_id = None;
        assert_eq!(
            local_read_selectors_from_tool(&noscope, &tool),
            Err(TransportError::SessionFenced),
            "missing trusted scope must be rejected before reading"
        );
    }

    #[test]
    fn check_local_read_admission_rejects_forgery_without_io() {
        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &tool_digest(&tool));
        assert!(matches!(
            check_local_read_admission(&envelope, &tool).expect("admitted query must validate"),
            LocalReadAdmission::Query(_)
        ));

        // A changed payload under the same envelope digest is rejected before
        // any read: the digest no longer binds the presented bytes.
        let mut changed = tool.clone();
        changed["arguments"]["query"] = serde_json::json!("subject:forged-subject");
        assert_eq!(
            check_local_read_admission(&envelope, &changed),
            Err(TransportError::SessionFenced),
            "changed payload digest must be rejected before reading"
        );

        // A tool bound to another capability is rejected the same way.
        let other_envelope = test_envelope("eliot.state", &tool_digest(&tool));
        assert_eq!(
            check_local_read_admission(&other_envelope, &tool),
            Err(TransportError::SessionFenced),
            "capability mismatch must be rejected before reading"
        );

        // Packet passes linkage as its own queue shape.
        let packet = packet_tool();
        let packet_envelope = test_envelope("eliot.packet", &tool_digest(&packet));
        assert!(matches!(
            check_local_read_admission(&packet_envelope, &packet)
                .expect("packet linkage must validate"),
            LocalReadAdmission::CampaignPacket { .. }
        ));
    }

    #[test]
    fn local_read_replay_serves_exact_result_without_redispatch() {
        use eliot_contracts::{canonical_json_bytes, sha256_hex};
        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &tool_digest(&tool));
        let receipt = HostRequestAdmissionReceipt::issue(&envelope).expect("receipt must issue");
        let mut record = requested_host_request_record(&envelope).expect("record must build");

        // A live row takes the fresh leg: no stored body, no replay.
        assert_eq!(
            local_read_replay_response(&receipt, &record, &envelope)
                .expect("live row must not fail"),
            None,
            "live operations never serve a stored body"
        );

        // A resulted row serves its exact bounded body with the revision inline.
        let body = serde_json::json!({
            "operation": "GetEvidencePack",
            "subject": "evidence-alpha",
            "evidence_pack": {"subject": "evidence-alpha"},
            "revision_heads": [{"key": "scope:kernel-session-1", "revision": 3}],
        });
        let digest = sha256_hex(&canonical_json_bytes(&body).expect("body must canonicalize"));
        record.result_digest = Some(digest.clone());
        record.result_response = Some(body.clone());
        let replayed = local_read_replay_response(&receipt, &record, &envelope)
            .expect("resulted row must serve")
            .expect("resulted row must replay");
        assert_eq!(
            replayed["value"]["record"]["result_digest"],
            serde_json::json!(digest),
            "the replay carries the exact stored digest"
        );
        assert_eq!(
            replayed["value"]["record"]["result_response"], body,
            "the replay carries the exact stored body"
        );
        let again = local_read_replay_response(&receipt, &record, &envelope)
            .expect("replay must be repeatable")
            .expect("replay must stay exact");
        assert_eq!(
            replayed, again,
            "replay is byte-exact across calls with no dispatch"
        );

        // A forged digest fails closed instead of serving.
        let mut forged = record.clone();
        forged.result_digest = Some("0".repeat(64));
        assert_eq!(
            local_read_replay_response(&receipt, &forged, &envelope),
            Err(TransportError::SessionFenced),
            "forged digest must be rejected before serving"
        );

        // A half-present pair never serves as an answer.
        let mut half = record.clone();
        half.result_response = None;
        assert_eq!(
            local_read_replay_response(&receipt, &half, &envelope)
                .expect("half-present pair must not fail"),
            None,
            "a half-present pair takes the fresh leg, never a partial serve"
        );
    }
}
