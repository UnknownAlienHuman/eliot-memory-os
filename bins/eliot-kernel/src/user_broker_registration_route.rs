//! Authenticated User Broker registration lifecycle ingress.
//!
//! Only a dedicated User Broker Session selected from the installer-pinned
//! OS peer role reaches this route. The request is joined to that live peer,
//! the current Kernel installation/epoch, the exact broker artifact and the
//! caller's one request identity before ORS is changed.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use eliot_contracts::{EpochId, StateFence};
use eliot_ors::{
    EpochIdentity, EpochLineage, OperationIdentity, OperationalPhase, OperationalRecordContext,
    OperationalRecordInput, OperationalRecoveryStore, StateFenceSnapshot, UserBrokerFence,
    UserBrokerRegistration,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::{Frame, ProtocolPayload, RequestIdentity};
use eliot_user_broker_core::{
    RegistrationGrant, RegistrationReceipt, RegistrationRequest, RegistrationStatus,
};

use super::user_broker_registration_authority::{
    LiveUserBrokerRegistration, UserBrokerSessionBinding,
};
use super::{
    FrameKind, KernelComposition, KernelFrameAction, KernelServiceState, MessageType, Session,
    TransportError, status_frame,
};

pub(crate) const USER_BROKER_MODULE_ID: &str = "eliot-user-broker";
pub(crate) const USER_BROKER_REGISTER_OPERATION: &str = "eliot.user-broker.register";
fn broker_digest<T: Serialize>(value: &T) -> Result<String, TransportError> {
    let bytes = serde_json::to_vec(value).map_err(|_| TransportError::SessionFenced)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn current_installation_id(kernel: &KernelComposition) -> Result<String, TransportError> {
    let service = kernel
        .service
        .lock()
        .map_err(|_| TransportError::SessionFenced)?;
    let binding = service
        .candidate_binding()
        .ok_or(TransportError::SessionFenced)?;
    Ok(binding.installation_id.as_str().to_owned())
}

fn peer_claims_registration(
    kernel: &KernelComposition,
    session: &Session,
    request: &RegistrationRequest,
    identity: &RequestIdentity,
    frame: &Frame,
    now: u64,
) -> Result<(String, StateFence, EpochId), TransportError> {
    request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    identity.validate()?;

    let Some(frame_request_id) = frame.request_id.as_ref() else {
        return Err(TransportError::SessionFenced);
    };
    let metadata = &identity.request.metadata;
    let identity_clock =
        i64::try_from(request.observed_at).map_err(|_| TransportError::SessionFenced)?;
    let peer_binding = session
        .peer
        .process_binding()
        .ok_or(TransportError::PeerIdentityUnavailable)?;
    let (process_id, windows_sid, interactive_session_id) = match &session.peer {
        eliot_ipc::PeerIdentity::Authenticated {
            process_id,
            user_identity,
            session_identity,
            ..
        } => (
            *process_id,
            user_identity.as_str(),
            session_identity.as_str(),
        ),
        eliot_ipc::PeerIdentity::Unavailable { .. } => {
            return Err(TransportError::PeerIdentityUnavailable);
        }
    };
    if peer_binding.process_id() != process_id
        || request.installation_id != current_installation_id(kernel)?
        || request.windows_sid != windows_sid
        || request.interactive_session_id != interactive_session_id
        || request.broker_process_id != process_id.to_string()
        || request.broker_artifact_digest.as_str()
            != kernel
                .user_broker_artifact_sha256
                .as_deref()
                .ok_or(TransportError::SessionFenced)?
        || request.protocol_generation != session.protocol_version
        || request.launch_nonce != session.launch_nonce
        || frame_request_id != &metadata.request_id
        || metadata.product_id.as_str() != "eliot-user-broker"
        || metadata.source_id.as_str() != "user-broker-transport"
        || metadata.session_id.is_some()
        || metadata.task_id.is_some()
        || metadata.clock.valid_time_ms != Some(identity_clock)
        || metadata.clock.known_time_ms != Some(identity_clock)
        || identity.deadline_unix_ms <= now
        || identity.deadline_unix_ms > request.lease_expires_at
        || request.observed_at > now
        || request.lease_expires_at <= now
        || &identity.request.state_fence != &session.module_generation.state_fence
        || &identity.request.state_fence != &metadata.state_fence
    {
        return Err(TransportError::SessionFenced);
    }

    let policy = kernel
        .front_door_policy
        .lock()
        .map_err(|_| TransportError::SessionFenced)?
        .clone();
    if !session
        .authority_epoch
        .is_same_authority(&policy.module_generation.state_fence.authority_epoch)
        || &session.module_generation.state_fence != &policy.module_generation.state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    Ok((
        request.installation_id.clone(),
        policy.module_generation.state_fence,
        session.authority_epoch.clone(),
    ))
}

fn ors_epoch_lineage(
    epoch: &EpochId,
    previous: Option<&EpochIdentity>,
) -> Result<EpochLineage, TransportError> {
    let current = EpochIdentity {
        lineage_id: eliot_ors::OpaqueLabel::new(epoch.lineage_id.as_str())
            .map_err(|_| TransportError::SessionFenced)?,
        epoch: epoch.sequence.get(),
    };
    let predecessor = previous.filter(|prior| *prior != &current).cloned();
    let lineage = EpochLineage {
        current,
        predecessor,
    };
    lineage
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(lineage)
}

fn registration_record(
    request: &RegistrationRequest,
    grant: &RegistrationGrant,
    subject_id: OperationIdentity,
    previous_epoch: Option<&EpochIdentity>,
    state_fence: &StateFence,
) -> Result<OperationalRecordInput, TransportError> {
    let registration_digest = broker_digest(&(
        request,
        grant.user_broker_epoch,
        &grant.authority_epoch,
        &grant.fence_id,
    ))?;
    let record_id =
        OperationIdentity::new(format!("user-broker-registration:{}", registration_digest))
            .map_err(|_| TransportError::SessionFenced)?;
    let authority_epoch = ors_epoch_lineage(&grant.authority_epoch, previous_epoch)?;
    let state_fence_snapshot =
        StateFenceSnapshot::capture(state_fence, grant.authority_epoch.sequence.get())
            .map_err(|_| TransportError::SessionFenced)?;
    state_fence_snapshot
        .validate_against_epoch(&grant.authority_epoch)
        .map_err(|_| TransportError::SessionFenced)?;
    let payload_bytes =
        serde_json::to_vec(&(request, grant)).map_err(|_| TransportError::SessionFenced)?;
    let payload_length =
        u64::try_from(payload_bytes.len()).map_err(|_| TransportError::SessionFenced)?;
    let locator = PlatformHandle::new(format!(
        "ors:user-broker-registration:{}",
        registration_digest
    ))
    .map_err(|_| TransportError::SessionFenced)?;
    let record = OperationalRecordInput::immutable_locator(
        OperationalRecordContext {
            record_id: record_id.clone(),
            subject_id,
            authority_epoch,
            state_fence: state_fence_snapshot,
            created_at_ms: i64::try_from(request.observed_at)
                .map_err(|_| TransportError::SessionFenced)?,
            cleanup_after_ms: None,
        },
        locator,
        broker_digest(&payload_bytes)?,
        payload_length,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    Ok(record)
}

impl KernelComposition {
    /// Routes the closed User Broker operation vocabulary from an admitted
    /// User Broker session. The first admitted mutation is registration;
    /// unsupported selectors remain fenced until their owning lifecycle
    /// route is present.
    #[allow(
        clippy::too_many_lines,
        reason = "the exact registration joins and ORS publish remain ordered at one authority boundary"
    )]
    pub(crate) fn dispatch_user_broker_operation(
        &self,
        session: &Session,
        frame: &Frame,
        operation: &str,
        payload: &Value,
        identity: &RequestIdentity,
    ) -> Result<Value, TransportError> {
        if session.module_generation.module_id.as_str() != USER_BROKER_MODULE_ID
            || !session.capabilities.iter().any(|value| value == operation)
            || !session.accepts(&session.authority_epoch, session.session_epoch)
            || self
                .service_state()
                .map_err(|_| TransportError::SessionFenced)?
                != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        if operation != USER_BROKER_REGISTER_OPERATION {
            return Err(TransportError::SessionFenced);
        }
        let request: RegistrationRequest =
            serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
        let now = super::unix_ms();
        let (installation_id, state_fence, authority_epoch) =
            peer_claims_registration(self, session, &request, identity, frame, now)?;
        let subject_id = OperationIdentity::new(format!(
            "user-broker-subject:{}",
            broker_digest(&(
                "user-broker-registration-subject-v1",
                &installation_id,
                &request.windows_sid,
                &request.interactive_session_id,
            ))?
        ))
        .map_err(|_| TransportError::SessionFenced)?;

        let mut live = self
            .user_broker_registration_authority
            .live
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if let Some(current) = live.get(&session.connection_id) {
            if current.session.matches(session)
                && current.registration == request
                && &current.request_identity == identity
                && current.receipt.expires_at > now
            {
                return serde_json::to_value(&current.grant)
                    .map_err(|_| TransportError::SessionFenced);
            }
            return Err(TransportError::SessionFenced);
        }

        let previous = self
            .p07_ors
            .load_user_broker_registration(&subject_id)
            .map_err(|_| TransportError::SessionFenced)?;
        let (expected, user_broker_epoch, previous_epoch) = match previous.as_ref() {
            None => (None, 1, None),
            Some(snapshot) if snapshot.phase() == OperationalPhase::Fenced => (
                Some(snapshot.receipt()),
                snapshot
                    .operation_order()
                    .checked_add(1)
                    .ok_or(TransportError::SessionFenced)?,
                Some(&snapshot.record().authority_epoch.current),
            ),
            // An Active ORS row is not a typed live registration. It cannot
            // be replayed into this process-local authority cell after a
            // restart or a lost session.
            Some(_) => return Err(TransportError::SessionFenced),
        };
        let fence_id = format!(
            "user-broker-fence-{}",
            broker_digest(&(&request, &authority_epoch, user_broker_epoch,))?
        );
        let grant_digest = broker_digest(&(
            &request,
            &authority_epoch,
            user_broker_epoch,
            &fence_id,
            request.lease_expires_at,
        ))?;
        let grant = RegistrationGrant {
            registration: request.clone(),
            authority_epoch: authority_epoch.clone(),
            user_broker_epoch,
            fence_id,
            expires_at: request.lease_expires_at,
            grant_digest,
        };
        let receipt = RegistrationReceipt {
            registration_digest: broker_digest(&(
                &request,
                user_broker_epoch,
                &authority_epoch,
                &grant.fence_id,
            ))?,
            installation_id,
            windows_sid: request.windows_sid.clone(),
            interactive_session_id: request.interactive_session_id.clone(),
            boot_session_id: request.boot_session_id.clone(),
            broker_process_id: request.broker_process_id.clone(),
            user_broker_epoch,
            authority_epoch: authority_epoch.clone(),
            fence_id: grant.fence_id.clone(),
            expires_at: grant.expires_at,
            status: RegistrationStatus::Active,
        };
        let input = registration_record(
            &request,
            &grant,
            subject_id.clone(),
            previous_epoch,
            &state_fence,
        )?;
        let ors_registration = UserBrokerRegistration::new(input.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let snapshot = self
            .p07_ors
            .register_user_broker(ors_registration, expected)
            .map_err(|_| TransportError::SessionFenced)?;
        if snapshot.phase() != OperationalPhase::Active
            || snapshot.record() != &input
            || snapshot.operation_order() == 0
        {
            return Err(TransportError::SessionFenced);
        }
        let store_receipt = snapshot.receipt().clone();
        live.insert(
            session.connection_id.clone(),
            LiveUserBrokerRegistration {
                session: UserBrokerSessionBinding::capture(session),
                registration: request,
                grant: grant.clone(),
                receipt,
                request_identity: identity.clone(),
                subject_id,
                authority_epoch,
                state_fence,
                store_receipt,
                store_operation_order: snapshot.operation_order(),
            },
        );
        serde_json::to_value(grant).map_err(|_| TransportError::SessionFenced)
    }

    /// Validates and answers one frame from the dedicated User Broker
    /// session. The outer operation selector is closed and the inner payload
    /// must be a plain JSON object with no adjacent command fields.
    pub(crate) fn dispatch_user_broker_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if frame.kind != FrameKind::Request || frame.message_type != MessageType::Execute {
            return Err(TransportError::SessionFenced);
        }
        let request_id = frame
            .request_id
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let identity = frame
            .request_identity
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if &identity.request.metadata.request_id != request_id {
            return Err(TransportError::SessionFenced);
        }
        let ProtocolPayload::Json(envelope) = &frame.payload else {
            return Err(TransportError::SessionFenced);
        };
        let object = envelope.as_object().ok_or(TransportError::SessionFenced)?;
        if object.len() != 2 {
            return Err(TransportError::SessionFenced);
        }
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        let payload = object.get("payload").ok_or(TransportError::SessionFenced)?;
        let value =
            self.dispatch_user_broker_operation(session, frame, operation, payload, identity)?;
        let mut reply = status_frame(session, FrameKind::Response, MessageType::Result, value)?;
        reply.request_id = Some(request_id.clone());
        Ok(KernelFrameAction::Reply(reply))
    }

    /// Removes one exact live broker registration before attempting the
    /// durable ORS fence. A failed ORS write still revokes local use; future
    /// connections fail closed on the remaining opaque Active row.
    pub fn fence_user_broker_session(&self, session: &Session) {
        let removed = self
            .user_broker_registration_authority
            .live
            .lock()
            .ok()
            .and_then(|mut live| {
                let existing = live.get(&session.connection_id)?;
                if !existing.session.matches(session) {
                    return None;
                }
                live.remove(&session.connection_id)
            });
        let Some(registration) = removed else {
            return;
        };
        let _ = self.persist_user_broker_fence(&registration);
    }

    fn persist_user_broker_fence(
        &self,
        registration: &LiveUserBrokerRegistration,
    ) -> Result<(), TransportError> {
        let now = super::unix_ms();
        let created_at_ms = i64::try_from(now).map_err(|_| TransportError::SessionFenced)?;
        let payload_bytes = serde_json::to_vec(&(
            "user-broker-session-fenced-v1",
            &registration.receipt.registration_digest,
            registration.session.connection_id(),
            registration.session.session_epoch(),
        ))
        .map_err(|_| TransportError::SessionFenced)?;
        let payload_length =
            u64::try_from(payload_bytes.len()).map_err(|_| TransportError::SessionFenced)?;
        let record_id = OperationIdentity::new(format!(
            "user-broker-fence:{}:{}",
            registration.receipt.registration_digest,
            registration.session.session_epoch()
        ))
        .map_err(|_| TransportError::SessionFenced)?;
        let epoch_lineage = ors_epoch_lineage(&registration.authority_epoch, None)?;
        let state_fence = StateFenceSnapshot::capture(
            &registration.state_fence,
            registration.authority_epoch.sequence.get(),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        state_fence
            .validate_against_epoch(&registration.authority_epoch)
            .map_err(|_| TransportError::SessionFenced)?;
        let locator = PlatformHandle::new(format!(
            "ors:user-broker-session-fence:{}",
            registration.receipt.registration_digest
        ))
        .map_err(|_| TransportError::SessionFenced)?;
        let input = OperationalRecordInput::immutable_locator(
            OperationalRecordContext {
                record_id,
                subject_id: registration.subject_id.clone(),
                authority_epoch: epoch_lineage,
                state_fence,
                created_at_ms,
                cleanup_after_ms: None,
            },
            locator,
            broker_digest(&payload_bytes)?,
            payload_length,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let fence = UserBrokerFence::new(input).map_err(|_| TransportError::SessionFenced)?;
        let snapshot = self
            .p07_ors
            .fence_user_broker(fence, &registration.store_receipt)
            .map_err(|_| TransportError::SessionFenced)?;
        if snapshot.phase() != OperationalPhase::Fenced
            || snapshot.operation_order() <= registration.store_operation_order
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }
}
