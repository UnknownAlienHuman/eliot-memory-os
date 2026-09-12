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

use super::{KernelComposition, TransportError, activation_deadline_expired, sha256_json, unix_ms};
use eliot_kernel_service::{AgentBridgeAdmissionDescriptor, KernelServiceState};
use eliot_ors::{
    CONTRACT_VERSION as ORS_CONTRACT_VERSION, HostRequestKind as OrsHostRequestKind,
    HostRequestRecord, HostRequestState, OpaqueLabel, OperationIdentity, OrsError,
};
use eliot_protocol::{
    AGENT_BRIDGE_PROCESS_BINDING_WIRE_ID, AgentActivationResolutionResult,
    AgentBridgePeerAdmissionReceipt, AgentBridgeProcessBinding, HostRequestAdmissionReceipt,
    HostRequestEnvelope, HostRequestKind, host_request_operation_id,
};

/// Prefix of the deterministic opaque operation handle derived by
/// [`host_request_operation_id`]. A parent operation reference carries the
/// parent envelope digest after this prefix; the digest is re-validated as
/// lowercase SHA-256 before any store lookup, so a malformed reference is an
/// unknown operation rather than a fence failure.
const HOST_REQUEST_OPERATION_ID_PREFIX: &str = "hostreq:";

/// Connection-scoped reference to one staged host-request operation.
///
/// The durable ORS record owns lifecycle state; this reference only lets
/// disconnect revocation fence the presenting connection's still-uncertain
/// operations without enumerating the store.
#[derive(Clone, Debug)]
pub(crate) struct HostRequestOperationRef {
    pub(crate) operation_id: String,
    pub(crate) request_digest: String,
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
    /// A missing ticket or a ticket without a retained result is an unknown
    /// operation; a result bound to another connection fails closed; a digest
    /// or fence mismatch is an identity conflict; a non-resolved disposition
    /// fails closed without yielding any binding.
    fn host_request_activation_resolution(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<AgentActivationResolutionResult, TransportError> {
        let activation_binding = envelope
            .activation_binding
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let ticket_connection = {
            let pending = self
                .agent_activation_pending
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            pending
                .entries
                .get(&activation_binding.ticket_id)
                .map(|entry| entry.ticket.connection_id.clone())
                .ok_or(TransportError::UnknownRequest)?
        };
        if ticket_connection != envelope.connection_id {
            return Err(TransportError::SessionFenced);
        }
        let result: AgentActivationResolutionResult = {
            let results = self
                .agent_activation_results
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            results
                .get(&activation_binding.ticket_id)
                .cloned()
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
            Ok(_) => Ok(()),
            Err(OrsError::InvalidTransition) => {
                let _ = self.generation_gateway.ors.advance_host_request(
                    &parent_operation,
                    &parent_digest,
                    HostRequestState::Unknown,
                    None,
                );
                Ok(())
            }
            Err(_) => Ok(()),
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
            });
        Ok(())
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
fn requested_host_request_record(
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
        authority_epoch: envelope.state_fence.authority_epoch.value(),
        generation: envelope.state_fence.resource_generation.value(),
        deadline_unix_ms: envelope.identity.deadline_unix_ms,
        state: HostRequestState::Requested,
        result_digest: None,
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
fn fence_one_host_request(
    composition: &KernelComposition,
    operation_ref: &HostRequestOperationRef,
) {
    let Ok(operation_id) = OperationIdentity::new(operation_ref.operation_id.clone()) else {
        return;
    };
    let current = match composition
        .generation_gateway
        .ors
        .load_host_request(&operation_id, &operation_ref.request_digest)
    {
        Ok(current) => current,
        Err(_) => return,
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
    if parent.authority_epoch != descriptor.authority_epoch.value()
        || parent.generation != descriptor.generation.value()
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}
