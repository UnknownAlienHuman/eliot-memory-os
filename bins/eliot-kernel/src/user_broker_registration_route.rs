//! Authenticated User Broker registration lifecycle ingress.
//!
//! Only a dedicated User Broker Session selected from the installer-pinned
//! OS peer role reaches this route. The request is joined to that live peer,
//! the current Kernel installation/epoch, the exact broker artifact and the
//! caller's one request identity before ORS is changed.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use eliot_contracts::{EpochId, StateFence};
use eliot_security_contracts::NativeResourceSelection;
use eliot_ors::{
    EpochIdentity, EpochLineage, OperationIdentity, OperationalPhase, OperationalRecordContext,
    OperationalRecordInput, OperationalRecoveryStore, StateFenceSnapshot, UserBrokerFence,
    UserBrokerHeartbeat, UserBrokerRegistration,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::{Frame, ProtocolPayload, RequestIdentity};
use eliot_user_broker_core::{
    RegistrationFenceReceipt, RegistrationFenceRequest, RegistrationGrant, RegistrationReceipt,
    RegistrationRequest, RegistrationStatus,
};

use super::user_broker_registration_authority::{
    LiveUserBrokerRegistration, UserBrokerFenceReplay, UserBrokerHeartbeatReplay,
    UserBrokerSessionBinding,
};
use super::{
    FrameKind, KernelComposition, KernelFrameAction, KernelServiceState, MessageType, Session,
    TransportError, status_frame,
};

pub(crate) const USER_BROKER_MODULE_ID: &str = "eliot-user-broker";
pub(crate) const USER_BROKER_REGISTER_OPERATION: &str = "eliot.user-broker.register";
pub(crate) const USER_BROKER_HEARTBEAT_OPERATION: &str = "eliot.user-broker.heartbeat";
pub(crate) const USER_BROKER_FENCE_OPERATION: &str = "eliot.user-broker.fence";
pub(crate) const USER_BROKER_VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION: &str =
    "eliot.user-broker.validate-native-resource-selection-current";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserBrokerHeartbeatPayload {
    registration: RegistrationReceipt,
    observed_at: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserBrokerResourceSelectionCurrentPayload {
    registration: RegistrationReceipt,
    selection: NativeResourceSelection,
    observed_at: u64,
}
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
) -> Result<(String, StateFence, EpochId, u32), TransportError> {
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
        || identity.request.state_fence != session.module_generation.state_fence
        || identity.request.state_fence != metadata.state_fence
    {
        return Err(TransportError::SessionFenced);
    }

    let policy = kernel
        .front_door_policy
        .lock()
        .map_err(|_| TransportError::SessionFenced)?
        .clone();
    if session.module_generation != policy.module_generation
        || session.module_generation.artifact_id.as_str()
            != kernel
                .user_broker_artifact_sha256
                .as_deref()
                .ok_or(TransportError::SessionFenced)?
        || !session
            .authority_epoch
            .is_same_authority(&policy.module_generation.state_fence.authority_epoch)
        || session.module_generation.state_fence != policy.module_generation.state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    Ok((
        request.installation_id.clone(),
        policy.module_generation.state_fence,
        session.authority_epoch.clone(),
        policy.heartbeat_ms,
    ))
}

fn bounded_grant_expiration(
    now: u64,
    lease_expires_at: u64,
    heartbeat_ms: u32,
) -> Result<u64, TransportError> {
    if heartbeat_ms == 0 {
        return Err(TransportError::SessionFenced);
    }
    let heartbeat_deadline = now
        .checked_add(u64::from(heartbeat_ms))
        .ok_or(TransportError::SessionFenced)?;
    let expires_at = lease_expires_at.min(heartbeat_deadline);
    if expires_at <= now {
        return Err(TransportError::SessionFenced);
    }
    Ok(expires_at)
}

fn validate_user_broker_operation_identity(
    kernel: &KernelComposition,
    session: &Session,
    frame: &Frame,
    identity: &RequestIdentity,
    registration: &RegistrationRequest,
    now: u64,
) -> Result<u32, TransportError> {
    identity.validate()?;
    let request_id = frame
        .request_id
        .as_ref()
        .ok_or(TransportError::SessionFenced)?;
    let metadata = &identity.request.metadata;
    let identity_clock = metadata
        .clock
        .valid_time_ms
        .ok_or(TransportError::SessionFenced)?;
    if request_id != &metadata.request_id
        || metadata.product_id.as_str() != USER_BROKER_MODULE_ID
        || metadata.source_id.as_str() != "user-broker-transport"
        || metadata.session_id.is_some()
        || metadata.task_id.is_some()
        || metadata.clock.known_time_ms != Some(identity_clock)
        || identity_clock <= 0
        || u64::try_from(identity_clock).map_err(|_| TransportError::SessionFenced)? > now
        || identity.deadline_unix_ms <= now
        || identity.request.state_fence != session.module_generation.state_fence
        || identity.request.state_fence != metadata.state_fence
    {
        return Err(TransportError::SessionFenced);
    }

    let policy = kernel
        .front_door_policy
        .lock()
        .map_err(|_| TransportError::SessionFenced)?
        .clone();
    let expected_artifact = kernel
        .user_broker_artifact_sha256
        .as_deref()
        .ok_or(TransportError::SessionFenced)?;
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
        || registration.installation_id != current_installation_id(kernel)?
        || registration.windows_sid != windows_sid
        || registration.interactive_session_id != interactive_session_id
        || registration.broker_process_id != process_id.to_string()
        || registration.broker_artifact_digest != expected_artifact
        || session.module_generation.module_id.as_str() != USER_BROKER_MODULE_ID
        || session.module_generation.artifact_id.as_str() != expected_artifact
        || registration.protocol_generation != session.protocol_version
        || registration.launch_nonce != session.launch_nonce
        || session.module_generation != policy.module_generation
        || !session
            .authority_epoch
            .is_same_authority(&policy.module_generation.state_fence.authority_epoch)
        || session.module_generation.state_fence != policy.module_generation.state_fence
        || policy.heartbeat_ms == 0
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(policy.heartbeat_ms)
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
        OperationIdentity::new(format!("user-broker-registration:{registration_digest}"))
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
        "ors:user-broker-registration:{registration_digest}"
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

fn heartbeat_record(
    grant: &RegistrationGrant,
    subject_id: OperationIdentity,
    identity: &RequestIdentity,
    state_fence: &StateFence,
) -> Result<OperationalRecordInput, TransportError> {
    let request_id = &identity.request.metadata.request_id;
    let record_id = OperationIdentity::new(format!(
        "user-broker-heartbeat:{}:{request_id}",
        broker_digest(&grant.registration)?
    ))
    .map_err(|_| TransportError::SessionFenced)?;
    let authority_epoch = ors_epoch_lineage(&grant.authority_epoch, None)?;
    let state_fence_snapshot =
        StateFenceSnapshot::capture(state_fence, grant.authority_epoch.sequence.get())
            .map_err(|_| TransportError::SessionFenced)?;
    state_fence_snapshot
        .validate_against_epoch(&grant.authority_epoch)
        .map_err(|_| TransportError::SessionFenced)?;
    let payload_bytes = serde_json::to_vec(&("user-broker-heartbeat-v1", grant, identity))
        .map_err(|_| TransportError::SessionFenced)?;
    let payload_length =
        u64::try_from(payload_bytes.len()).map_err(|_| TransportError::SessionFenced)?;
    let locator = PlatformHandle::new(format!(
        "ors:user-broker-heartbeat:{}:{request_id}",
        grant.grant_digest
    ))
    .map_err(|_| TransportError::SessionFenced)?;
    OperationalRecordInput::immutable_locator(
        OperationalRecordContext {
            record_id,
            subject_id,
            authority_epoch,
            state_fence: state_fence_snapshot,
            created_at_ms: identity
                .request
                .metadata
                .clock
                .valid_time_ms
                .ok_or(TransportError::SessionFenced)?,
            cleanup_after_ms: None,
        },
        locator,
        broker_digest(&payload_bytes)?,
        payload_length,
    )
    .map_err(|_| TransportError::SessionFenced)
}

fn explicit_fence_record(
    registration: &RegistrationReceipt,
    subject_id: OperationIdentity,
    state_fence: &StateFence,
    identity: &RequestIdentity,
    request: &RegistrationFenceRequest,
) -> Result<OperationalRecordInput, TransportError> {
    let request_id = &identity.request.metadata.request_id;
    let record_id = OperationIdentity::new(format!("user-broker-explicit-fence:{request_id}"))
        .map_err(|_| TransportError::SessionFenced)?;
    let authority_epoch = ors_epoch_lineage(&registration.authority_epoch, None)?;
    let state_fence_snapshot =
        StateFenceSnapshot::capture(state_fence, registration.authority_epoch.sequence.get())
            .map_err(|_| TransportError::SessionFenced)?;
    state_fence_snapshot
        .validate_against_epoch(&registration.authority_epoch)
        .map_err(|_| TransportError::SessionFenced)?;
    let payload_bytes = serde_json::to_vec(&("user-broker-explicit-fence-v1", request, identity))
        .map_err(|_| TransportError::SessionFenced)?;
    let payload_length =
        u64::try_from(payload_bytes.len()).map_err(|_| TransportError::SessionFenced)?;
    let locator = PlatformHandle::new(format!(
        "ors:user-broker-explicit-fence:{}:{request_id}",
        registration.registration_digest
    ))
    .map_err(|_| TransportError::SessionFenced)?;
    OperationalRecordInput::immutable_locator(
        OperationalRecordContext {
            record_id,
            subject_id,
            authority_epoch,
            state_fence: state_fence_snapshot,
            created_at_ms: identity
                .request
                .metadata
                .clock
                .valid_time_ms
                .ok_or(TransportError::SessionFenced)?,
            cleanup_after_ms: None,
        },
        locator,
        broker_digest(&payload_bytes)?,
        payload_length,
    )
    .map_err(|_| TransportError::SessionFenced)
}

fn registration_fence_receipt(
    request: &RegistrationFenceRequest,
) -> RegistrationFenceReceipt {
    RegistrationFenceReceipt {
        registration_digest: request.registration.registration_digest.clone(),
        windows_sid: request.registration.windows_sid.clone(),
        interactive_session_id: request.registration.interactive_session_id.clone(),
        user_broker_epoch: request.registration.user_broker_epoch,
        authority_epoch: request.registration.authority_epoch.clone(),
        fence_id: request.registration.fence_id.clone(),
        operation_id: request.operation_id.clone(),
        status: request.status,
    }
}

fn user_broker_fence_status_name(status: RegistrationStatus) -> Option<&'static str> {
    match status {
        RegistrationStatus::Active => None,
        RegistrationStatus::Draining => Some("draining"),
        RegistrationStatus::Closed => Some("closed"),
    }
}

fn user_broker_registration_snapshot_matches(
    snapshot: &eliot_ors::UserBrokerRegistrationSnapshot,
    registration: &LiveUserBrokerRegistration,
) -> bool {
    let store_receipt = snapshot.receipt().receipt();
    snapshot.phase() == OperationalPhase::Active
        && snapshot.operation_order() == registration.store_operation_order
        && snapshot.record() == &registration.store_record
        && snapshot.receipt() == &registration.store_receipt
        && store_receipt.record_id() == &registration.store_record.record_id
        && store_receipt.subject_id() == &registration.subject_id
        && store_receipt.operation_order() == registration.store_operation_order
        && store_receipt.phase() == OperationalPhase::Active
}

fn user_broker_heartbeat_snapshot_matches(
    snapshot: &eliot_ors::UserBrokerRegistrationSnapshot,
    input: &OperationalRecordInput,
    prior_order: u64,
) -> bool {
    let receipt = snapshot.receipt().receipt();
    snapshot.phase() == OperationalPhase::Active
        && snapshot.record() == input
        && snapshot.operation_order() > prior_order
        && receipt.record_id() == &input.record_id
        && receipt.subject_id() == &input.subject_id
        && receipt.operation_order() == snapshot.operation_order()
        && receipt.phase() == OperationalPhase::Active
}

fn user_broker_fence_snapshot_matches(
    snapshot: &eliot_ors::UserBrokerRegistrationSnapshot,
    input: &OperationalRecordInput,
    prior_order: u64,
) -> bool {
    let receipt = snapshot.receipt().receipt();
    snapshot.phase() == OperationalPhase::Fenced
        && snapshot.record() == input
        && snapshot.operation_order() > prior_order
        && receipt.record_id() == &input.record_id
        && receipt.subject_id() == &input.subject_id
        && receipt.operation_order() == snapshot.operation_order()
        && receipt.phase() == OperationalPhase::Fenced
}

fn load_live_user_broker_registration(
    kernel: &KernelComposition,
    registration: &LiveUserBrokerRegistration,
) -> Result<eliot_ors::UserBrokerRegistrationSnapshot, TransportError> {
    let snapshot = kernel
        .p07_ors
        .load_user_broker_registration(&registration.subject_id)
        .map_err(|_| TransportError::SessionFenced)?
        .ok_or(TransportError::SessionFenced)?;
    if !user_broker_registration_snapshot_matches(&snapshot, registration) {
        return Err(TransportError::SessionFenced);
    }
    Ok(snapshot)
}

fn fenced_user_broker_snapshot_matches(
    snapshot: &eliot_ors::UserBrokerRegistrationSnapshot,
    replay: &UserBrokerFenceReplay,
) -> bool {
    let receipt = snapshot.receipt().receipt();
    snapshot.phase() == OperationalPhase::Fenced
        && snapshot.operation_order() == replay.store_operation_order
        && snapshot.record() == &replay.store_record
        && snapshot.receipt() == &replay.store_receipt
        && receipt.record_id() == &replay.store_record.record_id
        && receipt.subject_id() == &replay.subject_id
        && receipt.operation_order() == replay.store_operation_order
        && receipt.phase() == OperationalPhase::Fenced
}

impl KernelComposition {
    /// Routes the closed User Broker operation vocabulary from an admitted
    /// User Broker session. Every selector is bound to the exact capabilities
    /// admitted on its authenticated session and the live ORS registration.
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
        let now = super::unix_ms();
        if operation == USER_BROKER_HEARTBEAT_OPERATION {
            let request: UserBrokerHeartbeatPayload = serde_json::from_value(payload.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            return self.dispatch_user_broker_heartbeat(session, frame, &request, identity, now);
        }
        if operation == USER_BROKER_FENCE_OPERATION {
            let request: RegistrationFenceRequest = serde_json::from_value(payload.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            return self.dispatch_user_broker_fence(session, frame, request, identity, now);
        }
        if operation == USER_BROKER_VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION {
            let request: UserBrokerResourceSelectionCurrentPayload =
                serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
            self.validate_user_broker_resource_selection_current(
                session, frame, &request, identity, now,
            )?;
            return serde_json::to_value(()).map_err(|_| TransportError::SessionFenced);
        }
        if operation != USER_BROKER_REGISTER_OPERATION {
            return Err(TransportError::SessionFenced);
        }
        if self
            .user_broker_registration_authority
            .fenced_replays
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .contains_key(&session.connection_id)
        {
            return Err(TransportError::SessionFenced);
        }
        let request: RegistrationRequest =
            serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
        let (installation_id, state_fence, authority_epoch, heartbeat_ms) =
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
        let registration_observed_at = request.observed_at;

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
                && self
                    .p07_ors
                    .load_user_broker_registration(&current.subject_id)
                    .ok()
                    .flatten()
                    .is_some_and(|snapshot| {
                        user_broker_registration_snapshot_matches(&snapshot, current)
                    })
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
        let grant_expires_at =
            bounded_grant_expiration(now, request.lease_expires_at, heartbeat_ms)?;
        let grant_digest = broker_digest(&(
            &request,
            &authority_epoch,
            user_broker_epoch,
            &fence_id,
            grant_expires_at,
        ))?;
        let grant = RegistrationGrant {
            registration: request.clone(),
            authority_epoch: authority_epoch.clone(),
            user_broker_epoch,
            fence_id,
            expires_at: grant_expires_at,
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
        let store_mutation = snapshot.receipt().receipt();
        if snapshot.phase() != OperationalPhase::Active
            || snapshot.record() != &input
            || snapshot.operation_order() == 0
            || store_mutation.record_id() != &input.record_id
            || store_mutation.subject_id() != &subject_id
            || store_mutation.operation_order() != snapshot.operation_order()
            || store_mutation.phase() != OperationalPhase::Active
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
                store_record: input,
                last_observed_at: registration_observed_at,
                heartbeat_replay: None,
            },
        );
        serde_json::to_value(grant).map_err(|_| TransportError::SessionFenced)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "heartbeat renewal must reconcile one exact identity with the live typed registration and ORS CAS"
    )]
    fn dispatch_user_broker_heartbeat(
        &self,
        session: &Session,
        frame: &Frame,
        request: &UserBrokerHeartbeatPayload,
        identity: &RequestIdentity,
        now: u64,
    ) -> Result<Value, TransportError> {
        let mut live = self
            .user_broker_registration_authority
            .live
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let current = live
            .get_mut(&session.connection_id)
            .ok_or(TransportError::SessionFenced)?;
        if !current.session.matches(session) {
            return Err(TransportError::SessionFenced);
        }
        let heartbeat_ms = validate_user_broker_operation_identity(
            self,
            session,
            frame,
            identity,
            &current.registration,
            now,
        )?;
        if request.observed_at > now
            || request.observed_at < current.registration.observed_at
            || request.registration.status != RegistrationStatus::Active
        {
            return Err(TransportError::SessionFenced);
        }

        let exact_replay = current.heartbeat_replay.as_ref().is_some_and(|replay| {
            replay.registration == request.registration
                && replay.observed_at == request.observed_at
                && replay.identity == *identity
                && replay.grant == current.grant
        });
        if exact_replay {
            if now >= current.receipt.expires_at {
                drop(live);
                self.fence_user_broker_session(session);
                return Err(TransportError::SessionFenced);
            }
            if load_live_user_broker_registration(self, current).is_err() {
                drop(live);
                self.fence_user_broker_session(session);
                return Err(TransportError::SessionFenced);
            }
            return serde_json::to_value(&current.grant)
                .map_err(|_| TransportError::SessionFenced);
        }

        if request.registration != current.receipt
            || current.receipt.status != RegistrationStatus::Active
            || request.observed_at < current.last_observed_at
        {
            return Err(TransportError::SessionFenced);
        }
        if now >= current.receipt.expires_at {
            drop(live);
            self.fence_user_broker_session(session);
            return Err(TransportError::SessionFenced);
        }
        if request.observed_at >= current.receipt.expires_at {
            return Err(TransportError::SessionFenced);
        }
        if load_live_user_broker_registration(self, current).is_err() {
            drop(live);
            self.fence_user_broker_session(session);
            return Err(TransportError::SessionFenced);
        }

        let grant_expires_at = bounded_grant_expiration(
            now,
            current.registration.lease_expires_at,
            heartbeat_ms,
        )?;
        if grant_expires_at <= current.receipt.expires_at {
            return Err(TransportError::SessionFenced);
        }
        let grant_digest = broker_digest(&(
            &current.registration,
            &current.authority_epoch,
            current.grant.user_broker_epoch,
            &current.grant.fence_id,
            grant_expires_at,
        ))?;
        let grant = RegistrationGrant {
            registration: current.registration.clone(),
            authority_epoch: current.authority_epoch.clone(),
            user_broker_epoch: current.grant.user_broker_epoch,
            fence_id: current.grant.fence_id.clone(),
            expires_at: grant_expires_at,
            grant_digest,
        };
        let input = heartbeat_record(
            &grant,
            current.subject_id.clone(),
            identity,
            &current.state_fence,
        )?;
        let prior_order = current.store_operation_order;
        let prior_receipt = current.store_receipt.clone();
        let write = UserBrokerHeartbeat::new(input.clone())
            .map_err(|_| TransportError::SessionFenced)
            .and_then(|heartbeat| {
                self.p07_ors
                    .heartbeat_user_broker(heartbeat, &prior_receipt)
                    .map_err(|_| TransportError::SessionFenced)
            });
        let snapshot = match write {
            Ok(snapshot) => Some(snapshot),
            Err(_) => self
                .p07_ors
                .load_user_broker_registration(&current.subject_id)
                .ok()
                .flatten()
                .filter(|snapshot| {
                    user_broker_heartbeat_snapshot_matches(snapshot, &input, prior_order)
                }),
        };
        let Some(snapshot) = snapshot.filter(|snapshot| {
            user_broker_heartbeat_snapshot_matches(snapshot, &input, prior_order)
        }) else {
            drop(live);
            self.fence_user_broker_session(session);
            return Err(TransportError::SessionFenced);
        };

        let previous_receipt = current.receipt.clone();
        current.receipt.expires_at = grant.expires_at;
        current.grant = grant.clone();
        current.store_receipt = snapshot.receipt().clone();
        current.store_operation_order = snapshot.operation_order();
        current.store_record = input;
        current.last_observed_at = request.observed_at;
        current.heartbeat_replay = Some(UserBrokerHeartbeatReplay {
            registration: previous_receipt,
            observed_at: request.observed_at,
            identity: identity.clone(),
            grant: grant.clone(),
        });
        serde_json::to_value(grant).map_err(|_| TransportError::SessionFenced)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "resource currentness joins one exact live registration and one exact ORS selection snapshot"
    )]
    fn validate_user_broker_resource_selection_current(
        &self,
        session: &Session,
        frame: &Frame,
        request: &UserBrokerResourceSelectionCurrentPayload,
        identity: &RequestIdentity,
        now: u64,
    ) -> Result<(), TransportError> {
        let mut live = self
            .user_broker_registration_authority
            .live
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let current = live
            .get_mut(&session.connection_id)
            .ok_or(TransportError::SessionFenced)?;
        if !current.session.matches(session) {
            return Err(TransportError::SessionFenced);
        }
        validate_user_broker_operation_identity(
            self,
            session,
            frame,
            identity,
            &current.registration,
            now,
        )?;
        if request.registration != current.receipt
            || current.receipt.status != RegistrationStatus::Active
            || request.observed_at > now
            || request.observed_at < current.last_observed_at
        {
            return Err(TransportError::SessionFenced);
        }
        if now >= current.receipt.expires_at {
            drop(live);
            self.fence_user_broker_session(session);
            return Err(TransportError::SessionFenced);
        }
        if load_live_user_broker_registration(self, current).is_err() {
            drop(live);
            self.fence_user_broker_session(session);
            return Err(TransportError::SessionFenced);
        }

        request
            .selection
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let expected_subject = OperationIdentity::new(request.selection.operation_ref.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let snapshot = self
            .p07_ors
            .load_user_broker_resource_selection(&expected_subject)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        let record = snapshot.record();
        let record_id = record
            .record_id()
            .map_err(|_| TransportError::SessionFenced)?;
        let subject_id = record
            .subject_id()
            .map_err(|_| TransportError::SessionFenced)?;
        let store_receipt = snapshot.receipt().receipt();
        if snapshot.phase() != OperationalPhase::Active
            || snapshot.operation_order() == 0
            || record.selection != request.selection
            || subject_id != expected_subject
            || store_receipt.record_id() != &record_id
            || store_receipt.subject_id() != &expected_subject
            || store_receipt.operation_order() != snapshot.operation_order()
            || store_receipt.phase() != OperationalPhase::Active
        {
            return Err(TransportError::SessionFenced);
        }

        let selection = &record.selection;
        let latest_expiration = [
            selection.expires_at,
            record.grant_expires_at,
            record.launch_lease_expires_at,
            record.introduction_expires_at,
            record.registration_expires_at,
            current.receipt.expires_at,
            current.registration.lease_expires_at,
        ]
        .into_iter()
        .min()
        .ok_or(TransportError::SessionFenced)?;
        if selection.principal_ref != current.receipt.windows_sid
            || selection.interactive_session_id != current.receipt.interactive_session_id
            || selection.registration_ref != current.receipt.registration_digest
            || selection.broker_epoch != current.receipt.user_broker_epoch
            || selection.authority_epoch != current.authority_epoch
            || selection.fence_id != current.receipt.fence_id
            || selection.state_fence != current.state_fence
            || record.registration_expires_at > current.registration.lease_expires_at
            || request.observed_at < selection.issued_at
            || request.observed_at >= latest_expiration
            || now >= latest_expiration
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "fencing must confirm exact request identity, current ORS receipt and terminal replay state"
    )]
    fn dispatch_user_broker_fence(
        &self,
        session: &Session,
        frame: &Frame,
        request: RegistrationFenceRequest,
        identity: &RequestIdentity,
        now: u64,
    ) -> Result<Value, TransportError> {
        let replay = self
            .user_broker_registration_authority
            .fenced_replays
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .get(&session.connection_id)
            .cloned();
        if let Some(replay) = replay {
            if !replay.session.matches(session)
                || replay.request != request
                || replay.identity != *identity
            {
                return Err(TransportError::SessionFenced);
            }
            validate_user_broker_operation_identity(
                self,
                session,
                frame,
                identity,
                &replay.registration,
                now,
            )?;
            let snapshot = self
                .p07_ors
                .load_user_broker_registration(&replay.subject_id)
                .map_err(|_| TransportError::SessionFenced)?
                .ok_or(TransportError::SessionFenced)?;
            if !fenced_user_broker_snapshot_matches(&snapshot, &replay) {
                return Err(TransportError::SessionFenced);
            }
            return serde_json::to_value(replay.receipt)
                .map_err(|_| TransportError::SessionFenced);
        }

        let mut live = self
            .user_broker_registration_authority
            .live
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let current = live
            .get_mut(&session.connection_id)
            .ok_or(TransportError::SessionFenced)?;
        if !current.session.matches(session)
            || request.registration != current.receipt
            || current.receipt.status != RegistrationStatus::Active
        {
            return Err(TransportError::SessionFenced);
        }
        validate_user_broker_operation_identity(
            self,
            session,
            frame,
            identity,
            &current.registration,
            now,
        )?;
        let Some(status_name) = user_broker_fence_status_name(request.status) else {
            return Err(TransportError::SessionFenced);
        };
        let expected_operation_id = format!(
            "user-broker-fence-{}-{status_name}",
            current.receipt.registration_digest
        );
        if request.operation_id.as_str() != expected_operation_id.as_str() {
            return Err(TransportError::SessionFenced);
        }
        if load_live_user_broker_registration(self, current).is_err() {
            drop(live);
            self.fence_user_broker_session(session);
            return Err(TransportError::SessionFenced);
        }

        let input = explicit_fence_record(
            &current.receipt,
            current.subject_id.clone(),
            &current.state_fence,
            identity,
            &request,
        )?;
        let prior_order = current.store_operation_order;
        let prior_receipt = current.store_receipt.clone();
        let write = UserBrokerFence::new(input.clone())
            .map_err(|_| TransportError::SessionFenced)
            .and_then(|fence| {
                self.p07_ors
                    .fence_user_broker(fence, &prior_receipt)
                    .map_err(|_| TransportError::SessionFenced)
            });
        let snapshot = match write {
            Ok(snapshot) => Some(snapshot),
            Err(_) => self
                .p07_ors
                .load_user_broker_registration(&current.subject_id)
                .ok()
                .flatten()
                .filter(|snapshot| {
                    user_broker_fence_snapshot_matches(snapshot, &input, prior_order)
                }),
        };
        let Some(snapshot) = snapshot.filter(|snapshot| {
            user_broker_fence_snapshot_matches(snapshot, &input, prior_order)
        }) else {
            drop(live);
            self.fence_user_broker_session(session);
            return Err(TransportError::SessionFenced);
        };

        let receipt = registration_fence_receipt(&request);
        let replay = UserBrokerFenceReplay {
            session: current.session.clone(),
            registration: current.registration.clone(),
            request,
            identity: identity.clone(),
            receipt: receipt.clone(),
            subject_id: current.subject_id.clone(),
            store_receipt: snapshot.receipt().clone(),
            store_operation_order: snapshot.operation_order(),
            store_record: input,
        };
        live.remove(&session.connection_id);
        drop(live);
        self.user_broker_registration_authority
            .fenced_replays
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .insert(session.connection_id.clone(), replay);
        serde_json::to_value(receipt).map_err(|_| TransportError::SessionFenced)
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
        if let Ok(mut replays) = self
            .user_broker_registration_authority
            .fenced_replays
            .lock()
            && replays
                .get(&session.connection_id)
                .is_some_and(|replay| replay.session.matches(session))
        {
            replays.remove(&session.connection_id);
        }
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
