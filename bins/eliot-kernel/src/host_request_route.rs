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
    Frame, FrameKind, KernelComposition, KernelFrameAction, MessageType, ProtocolPayload, Session,
    TransportError, activation_deadline_expired, sha256_json, status_frame, unix_ms,
};
use eliot_kernel_service::{AgentBridgeAdmissionDescriptor, KernelServiceState};
use eliot_ors::{
    CONTRACT_VERSION as ORS_CONTRACT_VERSION, HostRequestKind as OrsHostRequestKind,
    HostRequestRecord, HostRequestState, OpaqueLabel, OperationIdentity, OrsError,
};
use eliot_protocol::{
    AGENT_BRIDGE_PROCESS_BINDING_WIRE_ID, AgentActivationResolutionResult,
    AgentBridgePeerAdmissionReceipt, AgentBridgeProcessBinding, HOST_REQUEST_INVOKE_READ_WIRE_ID,
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestAdmissionReceipt, HostRequestEnvelope,
    HostRequestInvokeReadPayload, HostRequestKind, HostRequestResultBody, LocalReadAttempt,
    host_request_operation_id,
};
use eliot_store_api::{EVIDENCE_PACK_MAX_RECORDS, ScopeId};

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
/// receipt under `receipt` for rehydrate); the operation string only selects
/// which closed entry — admit, cancel, reconcile, or rehydrate — consumes it.
/// There is no generic JSON command dispatch: the envelope is decoded as the
/// typed [`HostRequestEnvelope`] (with its canonical digest check) and the
/// envelope kind is re-enforced by the callee.
pub(crate) const AGENT_HOST_REQUEST_SUBMIT_OPERATION: &str = "agent_host_request_submit";
pub(crate) const AGENT_HOST_REQUEST_CANCEL_OPERATION: &str = "agent_host_request_cancel";
pub(crate) const AGENT_HOST_REQUEST_RECONCILE_OPERATION: &str = "agent_host_request_reconcile";
pub(crate) const AGENT_HOST_REQUEST_REHYDRATE_OPERATION: &str = "agent_host_request_rehydrate";
/// Closed invoke-read entry for local reads (Implements #18: local read result).
///
/// Carries the exact envelope plus the exact canonical tool bytes it admits,
/// so tool linkage (capability + payload digest) is re-checked before any
/// read and the exact bounded result with its revision can be served back
/// from the durable record without re-dispatch. The envelope stays
/// digest-only in spirit; the tool bytes only prove the presented operation
/// is the admitted one.
pub(crate) const AGENT_HOST_REQUEST_INVOKE_READ_OPERATION: &str =
    "agent_host_request_invoke_read";

/// Bound on queued local-read pairs for the outbound-only eliotd poller.
///
/// Mirrors the bounded activation replay/result ledgers (64): the durable ORS
/// record owns lifecycle state, so eviction only drops daemon-leg queue
/// memory and never fabricates admission.
const MAX_QUEUED_LOCAL_READS: usize = 64;

/// Returns whether the operation string selects the P-04 host-request route.
pub(crate) fn is_host_request_operation(operation: &str) -> bool {
    matches!(
        operation,
        AGENT_HOST_REQUEST_SUBMIT_OPERATION
            | AGENT_HOST_REQUEST_CANCEL_OPERATION
            | AGENT_HOST_REQUEST_RECONCILE_OPERATION
            | AGENT_HOST_REQUEST_REHYDRATE_OPERATION
            | AGENT_HOST_REQUEST_INVOKE_READ_OPERATION
    )
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
    /// Governed attempt ownership for the queued pair, replacing the former
    /// time-only claim lease. Never time-expires; only explicit
    /// retire/fence transitions invalidate it.
    pub(crate) local_read_attempt: LocalReadAttemptState,
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
        envelope
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = unix_ms();
        let expired = activation_deadline_expired(now, envelope.identity.deadline_unix_ms);

        let (descriptor, receipt) = self.host_request_connection_gate(envelope)?;
        self.host_request_service_gate(&descriptor, envelope)?;
        let binding = bridge_process_binding(&descriptor, &receipt, &envelope.connection_id)?;

        // Activation consumes the exact retained typed result. The resolver is
        // never invoked here; a missing ticket or result is an unknown
        // operation, a digest or fence mismatch is an identity conflict, and a
        // non-resolved disposition fails closed without a Session.
        let resolution: Option<AgentActivationResolutionResult> =
            if envelope.kind == HostRequestKind::Activation {
                Some(self.host_request_activation_resolution(envelope)?)
            } else {
                None
            };
        let admission_receipt = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            service
                .admit_host_request(envelope, &descriptor, &binding, resolution.as_ref())
                .map_err(|_| TransportError::SessionFenced)?
        };

        let requested = requested_host_request_record(envelope)?;
        let operation_id = OperationIdentity::new(host_request_operation_id(envelope))
            .map_err(|_| TransportError::SessionFenced)?;
        let stored = self
            .generation_gateway
            .ors
            .stage_host_request(&requested)
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
            self.note_host_request_operation(envelope)?;
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

        self.note_host_request_operation(envelope)?;
        Ok((admission_receipt, admitted))
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
    /// No semantic dispatch happens here: producing a fresh answer for
    /// `eliot.query`/`eliot.packet` requires the Governor read owner
    /// (`ReadService::query` over the canonical store), which lives outside
    /// this binary's lane (see the module HANDOFF below). This entry owns
    /// admission, linkage rejection, and exact readback; the
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
        let (receipt, record) = self.admit_host_request_envelope(envelope)?;
        // Queue admitted `eliot.query` pairs for the outbound-only eliotd
        // poller (`local_read_claim`, Implements #18). Packet admissions and
        // malformed selectors never queue; enqueue is best-effort and never
        // fails admission (the ORS record is already staged above).
        if matches!(
            check_local_read_admission(envelope, tool),
            Ok(Some(_))
        ) {
            let _ = self.enqueue_local_read_pair(envelope, tool);
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

    /// Fences every indexed host request after a bridge profile promotion.
    ///
    /// Promotion replaces the live profile and revokes all connections, so no
    /// presenting connection survives: every still-uncertain indexed operation
    /// is fenced to `Unknown` under the same owner-continuation rules as the
    /// per-connection fence. Like revocation, this never fails.
    pub(super) fn fence_all_host_requests(&self) {
        let outstanding = match self.host_request_connection_index.lock() {
            Ok(mut index) => std::mem::take(&mut *index)
                .into_values()
                .flatten()
                .collect::<Vec<_>>(),
            Err(_) => return,
        };
        for operation_ref in &outstanding {
            fence_one_host_request(self, operation_ref);
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
            Err(_) => return,
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
    fn host_request_connection_gate(
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
    /// The canonical v2 envelope ledger (`pending.results`, retained with its
    /// submission phase by the production submit path) is authoritative and is
    /// read first; the unenveloped P-04 raw map is a compatibility fallback.
    /// A changed same-ticket entry across the two ledgers is an identity
    /// conflict instead of a silent preference: one ticket owns at most one
    /// result identity. An exact digest match across both legs stays
    /// idempotent. A projected entry stays answerable: the pending
    /// entry is consumed after bridge projection but the retained record keeps
    /// the exact ticket connection, so a retried envelope for the same ticket
    /// answers from the known result instead of falling back to unknown. A
    /// missing ticket or a ticket without a retained result is an unknown
    /// operation; a result bound to another connection fails closed; a digest
    /// or fence mismatch is an identity conflict; a non-resolved disposition
    /// fails closed without yielding any binding.
    pub(super) fn host_request_activation_resolution(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<AgentActivationResolutionResult, TransportError> {
        let activation_binding = envelope
            .activation_binding
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let (entry_connection, retained) = {
            let pending = self
                .agent_activation_pending
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let entry_connection = pending
                .entries
                .get(&activation_binding.ticket_id)
                .map(|entry| entry.ticket.connection_id.clone());
            let retained = pending.results.get(&activation_binding.ticket_id).cloned();
            (entry_connection, retained)
        };
        if let Some(ticket_connection) = entry_connection {
            if ticket_connection != envelope.connection_id {
                return Err(TransportError::SessionFenced);
            }
        } else if let Some(record) = retained.as_ref() {
            // Projected entry consumed: fail closed on the retained ticket
            // connection before answering from the known result.
            if record.ticket_connection != envelope.connection_id {
                return Err(TransportError::SessionFenced);
            }
        } else {
            // No pending entry and no canonical retention: the raw
            // compatibility leg stays entry-gated so a cross-connection
            // replay cannot fabricate a result.
            return Err(TransportError::UnknownRequest);
        }
        let result: AgentActivationResolutionResult = if let Some(record) = retained {
            // Cross-ledger conflict check: one ticket owns at most one
            // result identity across the canonical v2 retention and the raw
            // P-04 compatibility leg. A changed same-ticket entry in the raw
            // leg conflicts instead of double-applying by silent preference;
            // an exact digest match across both legs stays idempotent.
            let raw_conflicts = {
                let results = self
                    .agent_activation_results
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?;
                results
                    .get(&activation_binding.ticket_id)
                    .is_some_and(|raw| raw.result.result_sha256 != record.result.result_sha256)
            };
            if raw_conflicts {
                return Err(TransportError::IdentityConflict);
            }
            record.result
        } else {
            let results = self
                .agent_activation_results
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            results
                .get(&activation_binding.ticket_id)
                .cloned()
                .map(|record| record.result)
                .ok_or(TransportError::UnknownRequest)?
        };
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
    fn note_host_request_operation(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<(), TransportError> {
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        index
            .entry(envelope.connection_id.clone())
            .or_default()
            .push(HostRequestOperationRef {
                operation_id: host_request_operation_id(envelope),
                request_digest: envelope.envelope_sha256.clone(),
                local_read_envelope: None,
                local_read_tool: None,
                local_read_attempt: LocalReadAttemptState::default(),
            });
        Ok(())
    }
}

/// Process-wide monotonic salt for local-read queue lifecycles.
///
/// Bumped at every enqueue so each queue lifecycle mints attempt identities
/// no earlier lifecycle can collide with, even when the fencing generation
/// restarts at 1 after retire or fence. Strictly increasing within a boot;
/// across restarts the composition boot nonce disambiguates.
static LOCAL_READ_ENQUEUE_SALT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

impl KernelComposition {
    /// Queues one admitted local-read pair for the daemon poller.
    ///
    /// Called best-effort from [`Self::invoke_read_host_request`] after the
    /// full admission gate, so only linkage-checked `eliot.query` pairs with
    /// valid selectors arrive here. An exact replay (same operation and
    /// digest already queued) is idempotent and never duplicates; when the
    /// bounded queue is full the oldest queued pair is evicted (daemon-leg
    /// memory only — the durable ORS record is untouched).
    pub(crate) fn enqueue_local_read_pair(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
    ) -> Result<(), TransportError> {
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = host_request_operation_id(envelope);
        for refs in index.values() {
            for candidate in refs {
                if candidate.operation_id == operation_id
                    && candidate.request_digest == envelope.envelope_sha256
                    && candidate.local_read_envelope.is_some()
                {
                    return Ok(());
                }
            }
        }
        let queued = index
            .values()
            .flatten()
            .filter(|candidate| candidate.local_read_envelope.is_some())
            .count();
        if queued >= MAX_QUEUED_LOCAL_READS {
            for refs in index.values_mut() {
                if let Some(position) = refs
                    .iter()
                    .position(|candidate| candidate.local_read_envelope.is_some())
                {
                    refs.remove(position);
                    break;
                }
            }
        }
        index
            .entry(envelope.connection_id.clone())
            .or_default()
            .push(HostRequestOperationRef {
                operation_id,
                request_digest: envelope.envelope_sha256.clone(),
                local_read_envelope: Some(envelope.clone()),
                local_read_tool: Some(tool.clone()),
                // The durable claim record is written at enqueue, before any
                // poll: unclaimed (`generation == 0`) until the first claim
                // mints fencing generation 1. The salt makes this lifecycle's
                // identities unique even if the pair is re-enqueued later. No
                // time lease is involved.
                local_read_attempt: LocalReadAttemptState {
                    enqueue_salt: LOCAL_READ_ENQUEUE_SALT.fetch_add(
                        1,
                        std::sync::atomic::Ordering::SeqCst,
                    ),
                    ..LocalReadAttemptState::default()
                },
            });
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
    pub(crate) fn retire_local_read_pair(&self, operation_id: &str, request_digest: &str) {
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
        body.validate()
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
        let live = self.live_local_read_attempt(&body.operation_id, &body.request_sha256)?;
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
                .and_then(|candidate| candidate.local_read_envelope.clone())
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
        self.retire_local_read_pair(&body.operation_id, &body.request_sha256);
        Ok(LocalReadSubmitDisposition::Persisted(Box::new(persisted)))
    }
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
                let (receipt, record) = self.admit_host_request_envelope(&envelope)?;
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
/// `intent_mode` is the presented `snake_case` query mode. `eliot.packet` is
/// not a query and yields no selectors; the packet path keeps its
/// admission-only behaviour untouched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalReadSelectors {
    pub(crate) scope_id: ScopeId,
    pub(crate) subject: String,
    pub(crate) max_records: u32,
    pub(crate) intent_mode: String,
}

/// Derives the closed local-read selectors from one linked envelope+tool pair.
///
/// Returns `Ok(None)` for `eliot.packet` (non-goal: the packet path keeps its
/// admission-only behaviour and never reaches the read leg). Fails closed as
/// `SessionFenced` for any other tool name, for a capability mismatch, for a
/// `CurrentPosition` intent (which never admits `GetEvidencePack`), for a
/// present `exact_resource_uri` (exact expansion uses the resource path, not
/// a query), for a non-exact `subject:` selector, and for a missing or blank
/// trusted scope. Mirrors the `plan_evidence_pack_query` rules field-for-field
/// without taking an MCP edge; linkage (capability + payload digest) must
/// already be proven by the caller through [`HostRequestInvokeReadPayload`].
/// Pure: deriving selectors performs no store IO.
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
    Ok(Some(LocalReadSelectors {
        scope_id,
        subject: subject.to_owned(),
        max_records: EVIDENCE_PACK_MAX_RECORDS,
        intent_mode: mode.to_owned(),
    }))
}

/// Validates one local-read admission before any store read (no IO).
///
/// Runs the exact invoke-read linkage gate ([`HostRequestInvokeReadPayload`])
/// plus the closed selector derivation, so a changed payload digest, a forged
/// descriptor or capability, or a malformed selector is rejected before the
/// caller performs any Gateway IO. Pure: validation performs no IO by
/// construction, which is the rejection-before-reading proof.
pub(crate) fn check_local_read_admission(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<Option<LocalReadSelectors>, TransportError> {
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|_| TransportError::SessionFenced)?;
    local_read_selectors_from_tool(envelope, tool)
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

/// Expected route identity for one Watchdog spool export batch.
///
/// The EBP `payload_type`/`message_type` binding for
/// `watchdog-spool-batch-v1` is deferred (protocol file out of scope; see PR
/// residual). Until it lands, this closed route string is the mechanical
/// route check below; no new payload type is created here.
pub(crate) const WATCHDOG_SPOOL_BATCH_ROUTE: &str = "watchdog-spool-batch-v1";

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
    reason = "the mechanical envelope joins stay explicit until the EBP payload_type lands"
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
    fn local_read_packet_yields_no_selectors_and_keeps_admission_path() {
        let tool = packet_tool();
        let envelope = test_envelope("eliot.packet", &tool_digest(&tool));
        assert_eq!(
            local_read_selectors_from_tool(&envelope, &tool)
                .expect("packet must not fail selector derivation"),
            None,
            "packet stays on the admission-only leg and never reaches the read"
        );
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
        assert!(
            check_local_read_admission(&envelope, &tool)
                .expect("admitted query must validate")
                .is_some(),
            "the admitted query carries selectors"
        );

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

        // Packet passes linkage and yields no selectors: admission-only leg.
        let packet = packet_tool();
        let packet_envelope = test_envelope("eliot.packet", &tool_digest(&packet));
        assert_eq!(
            check_local_read_admission(&packet_envelope, &packet)
                .expect("packet linkage must validate"),
            None,
            "packet keeps the admission-only path"
        );
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
