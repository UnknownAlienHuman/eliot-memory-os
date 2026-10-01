//! Mechanical wire translation/transport of Kernel-issued authority for the
//! User Broker ↔ Kernel authenticated boundary (B.8 Kernel ↔ User Broker).
//!
//! Architecture anchors: A12.2 Principal, Session и visibility, A12.3 Один
//! governed write path, A13.2 Kernel и failure domains (bounded A12 Security
//! and A13 Resilience). Implementation anchors: I1.3 Optional и on-demand
//! processes, B.1 Kernel ↔ Daemon, P.3 Kernel control boundary, I5.27
//! canonical operation identity, and I2.23 Capability-family topology and
//! crate extraction decisions.
//!
//! This module is a thin transport: it mints one fresh exact
//! [`RequestIdentity`] per Kernel transaction through the broker-owned
//! operation-identity issuer, installs it on the shared client for that
//! single call, forwards the `AuthorityPort` call over
//! `SharedKernelClient::transact_json`, and maps `KernelClientError` to
//! `PortError` without retry, cache, default, lease/token minting, semantic
//! decision, or canonical state ownership. No ambient client-global identity
//! is ever reused across operations: exact retry of one revision reuses its
//! own identity, and idempotency reuse across different canonical bytes
//! fails with an identity conflict before any Kernel effect. All authority
//! remains Kernel-issued.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_protocol::RequestIdentity;
use eliot_security_contracts::NativeResourceSelection;
use eliot_user_broker_core::{
    AuthorityPort, LaunchGrant, LaunchRequest, PortError, RegistrationFenceReceipt,
    RegistrationFenceRequest, RegistrationGrant, RegistrationReceipt, RegistrationRequest,
    RegistrationStatus,
};

use super::SharedKernelClient;
use crate::operation_identity::{
    AUTHORIZE_LAUNCH_OPERATION, BrokerOperation, FENCE_OPERATION, HEARTBEAT_OPERATION,
    IssuerHandle, OPERATOR_SESSION_TOKEN_OPERATION, OPERATOR_SESSION_TOKEN_OPERATION_PREFIX,
    OperationIdentityError, REGISTER_OPERATION,
    VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION,
};

/// One Operator session-token request, as this broker observes it for a single
/// connecting UI process.
///
/// Every field is broker-observed OS evidence or the exact binding this broker
/// issued; none of it is a Kernel authority value. The Kernel re-validates the
/// shape, binds it to its own live authority triple, and mints the token.
///
/// The closed Kernel carrier for this request is
/// `bins/eliot-kernel/src/daemon_request_dispatch.rs::OperatorSessionTokenOperation`;
/// the two declarations are the same wire contract and are paired field for
/// field, in the same way the Notify launch grant pairs its Kernel carrier with
/// `eliot_kernel_service::NotifyGrantInputs`.
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct OperatorSessionTokenRequest {
    pub(crate) registration_digest: String,
    pub(crate) handoff_nonce: String,
    pub(crate) windows_sid: String,
    pub(crate) interactive_session_id: String,
    pub(crate) client_process_id: String,
    pub(crate) client_image_path: String,
    pub(crate) role: String,
    pub(crate) capabilities: Vec<String>,
}

/// The Kernel-issued session token for exactly one binding.
///
/// The echoed evidence is compared with the request that produced it, the
/// observed authority epoch with the live registration this broker holds, and
/// the lease with this broker's live clock, before the token is recorded
/// against the binding. A response that names a different binding, a missing
/// token, or an elapsed lease is refused: a presented value is not proof, and
/// the only proof of Kernel issuance is the Kernel's own reply.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorSessionTokenGrant {
    pub(crate) operation_id: String,
    pub(crate) token: String,
    pub(crate) issued_at_unix_ms: u64,
    pub(crate) expires_at_unix_ms: u64,
    pub(crate) generation: u64,
    pub(crate) authority_epoch: eliot_contracts::EpochId,
    pub(crate) state_fence: eliot_contracts::StateFence,
    pub(crate) registration_digest: String,
    pub(crate) handoff_nonce: String,
    pub(crate) windows_sid: String,
    pub(crate) interactive_session_id: String,
    pub(crate) client_process_id: String,
    pub(crate) client_image_path: String,
    pub(crate) role: String,
    pub(crate) capabilities: Vec<String>,
}

impl OperatorSessionTokenGrant {
    /// Requires the grant to be the Kernel's answer to exactly this request,
    /// issued under the authority epoch of the live registration, and current
    /// on this broker's live clock.
    pub(crate) fn validate_for(
        &self,
        request: &OperatorSessionTokenRequest,
        live: &RegistrationReceipt,
        observed_at_unix_ms: u64,
    ) -> Result<(), PortError> {
        let mismatched = self.registration_digest != request.registration_digest
            || self.handoff_nonce != request.handoff_nonce
            || self.windows_sid != request.windows_sid
            || self.interactive_session_id != request.interactive_session_id
            || self.client_process_id != request.client_process_id
            || self.client_image_path != request.client_image_path
            || self.role != request.role
            || self.capabilities != request.capabilities;
        if mismatched {
            return Err(PortError::Invalid(
                "operator session token grant names a different binding".to_owned(),
            ));
        }
        if self.token.len() != 64
            || !self
                .token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(PortError::Invalid(
                "operator session token is not a lowercase SHA-256 token".to_owned(),
            ));
        }
        // The grant must be the answer to *this* operation, not merely some
        // operation. The Kernel mints the id deterministically from the
        // one-shot handoff nonce, so the expected id is derivable here and is
        // compared exactly; a shape check on a non-empty id would accept a
        // reply about a different operation.
        let expected_operation_id = format!(
            "{OPERATOR_SESSION_TOKEN_OPERATION_PREFIX}{}",
            request.handoff_nonce
        );
        if self.operation_id != expected_operation_id || self.generation == 0 {
            return Err(PortError::Invalid(
                "operator session token grant carries a different operation identity".to_owned(),
            ));
        }
        // The grant's own authority triple must be internally exact and must
        // name the authority epoch of the live registration this broker holds.
        // The broker cannot re-observe the Kernel's generation or fence, so it
        // records them as the Kernel's own observation rather than pretending
        // to have proven them a second time.
        if !self
            .authority_epoch
            .is_same_authority(&live.authority_epoch)
            || !self
                .state_fence
                .authority_epoch
                .is_same_authority(&self.authority_epoch)
            || self.state_fence.resource_generation.value() != self.generation
        {
            return Err(PortError::Invalid(
                "operator session token was issued under a different Kernel authority epoch or fence"
                    .to_owned(),
            ));
        }
        if self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || observed_at_unix_ms >= self.expires_at_unix_ms
        {
            return Err(PortError::Invalid(
                "operator session token is not current on the live clock".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The closed Kernel reply envelope for one session-token request. The Kernel
/// projects it at `bind_operator_session_token_operation`; a reply of any other
/// kind is not this operation's answer and is refused.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorSessionTokenReply {
    kind: String,
    value: OperatorSessionTokenGrant,
}

fn kernel_port_error(error: eliot_cli::kernel_client::KernelClientError) -> PortError {
    match error {
        eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(_) => PortError::Unavailable,
        eliot_cli::kernel_client::KernelClientError::UnknownOutcome(_)
        | eliot_cli::kernel_client::KernelClientError::RestartRequired(_) => PortError::Unknown,
        eliot_cli::kernel_client::KernelClientError::MissingRequestIdentity => {
            PortError::Invalid("missing authenticated RequestIdentity".to_owned())
        }
        eliot_cli::kernel_client::KernelClientError::Configuration(detail)
        | eliot_cli::kernel_client::KernelClientError::Rejected(detail) => {
            PortError::Invalid(detail)
        }
    }
}

fn identity_port_error(error: OperationIdentityError) -> PortError {
    match error {
        OperationIdentityError::IdentityConflict(detail) => {
            PortError::Invalid(format!("operation identity conflict: {detail}"))
        }
        other => PortError::Invalid(format!("operation identity rejected: {other}")),
    }
}

fn now_unix_ms() -> Result<u64, PortError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| PortError::Invalid(error.to_string()))
        .and_then(|duration| {
            u64::try_from(duration.as_millis())
                .map_err(|error| PortError::Invalid(error.to_string()))
        })
        .and_then(|now| {
            if now == 0 {
                Err(PortError::Invalid(
                    "broker clock observation is zero".to_owned(),
                ))
            } else {
                Ok(now)
            }
        })
}

fn kernel_call(
    client: &SharedKernelClient,
    operation: &str,
    payload: serde_json::Value,
    identity: RequestIdentity,
) -> Result<serde_json::Value, PortError> {
    identity
        .validate()
        .map_err(|error| PortError::Invalid(format!("operation identity invalid: {error}")))?;
    let mut client = client.lock().map_err(|_| PortError::Unknown)?;
    // The identity is installed for this single transaction only. The next
    // transaction mints and installs its own; nothing ambient is reused.
    client.set_request_identity(identity);
    client
        .transact_json(operation, payload)
        .map_err(kernel_port_error)
}

pub(crate) struct KernelAuthorityPort {
    pub(crate) client: SharedKernelClient,
    pub(crate) issuer: IssuerHandle,
}

impl KernelAuthorityPort {
    fn issue(
        &self,
        operation: BrokerOperation,
        payload: &serde_json::Value,
    ) -> Result<RequestIdentity, PortError> {
        let now = now_unix_ms()?;
        let mut guard = self.issuer.lock().map_err(|_| PortError::Unknown)?;
        let issued = match operation {
            BrokerOperation::Register => guard.issue_register(payload, now),
            BrokerOperation::HeartbeatRenewal => guard.issue_heartbeat(payload, now),
            BrokerOperation::FenceLogoff => guard.issue_fence(payload, now),
            BrokerOperation::OperatorSessionToken => {
                guard.issue_operator_session_token(payload, now)
            }
            BrokerOperation::ValidateNativeResourceSelectionCurrent => {
                guard.issue_native_resource_selection_currentness(payload, now)
            }
            BrokerOperation::AuthorizeLaunch => {
                return Err(PortError::Invalid(
                    "authorize-launch requires its caller launch binding".to_owned(),
                ));
            }
        }
        .map_err(identity_port_error)?;
        Ok(issued.identity)
    }
}

impl KernelAuthorityPort {
    /// Requests the fresh, short-lived Kernel session token for one exact
    /// Operator binding (I11.8).
    ///
    /// This is a transport method, not a mint: the broker forwards the exact
    /// binding evidence it observed, and the returned grant is the Kernel's
    /// own answer, validated against that same request, against the authority
    /// epoch of the live registration, and against this broker's live clock.
    /// A Kernel that is closed, fenced, unreachable, or answers about a
    /// different binding produces no token at all, so no handoff can be
    /// challenged while a Kernel session token is unobtainable.
    pub(crate) fn operator_session_token(
        &self,
        request: &OperatorSessionTokenRequest,
        live: &RegistrationReceipt,
    ) -> Result<OperatorSessionTokenGrant, PortError> {
        let payload =
            serde_json::to_value(request).map_err(|error| PortError::Invalid(error.to_string()))?;
        let now = now_unix_ms()?;
        let identity = self
            .issuer
            .lock()
            .map_err(|_| PortError::Unknown)?
            .issue_operator_session_token(&payload, now)
            .map_err(identity_port_error)?
            .identity;
        let raw = kernel_call(
            &self.client,
            OPERATOR_SESSION_TOKEN_OPERATION,
            payload,
            identity,
        )?;
        let reply: OperatorSessionTokenReply = serde_json::from_value(raw).map_err(|error| {
            PortError::Invalid(format!("decode operator session token reply: {error}"))
        })?;
        if reply.kind != "operator_session_token" {
            return Err(PortError::Invalid(
                "Kernel reply is not an operator session token".to_owned(),
            ));
        }
        reply
            .value
            .validate_for(request, live, now_unix_ms()?)
            .map_err(|error| {
                PortError::Invalid(format!("operator session token refused: {error}"))
            })?;
        Ok(reply.value)
    }
}

/// Typed User Broker evidence bundle for the interactive-maintenance gate
/// (I14.22 W3, issue #1692).
///
/// Every stored field is an output of one existing owner operation on this
/// same [`AuthorityPort`] transport — the Kernel-issued registration sealed
/// from `register`, the lease-renewal grant from `heartbeat`, and the launch
/// grant state from `authorize_launch`. The latest revocation/fence
/// observation from `fence` rides along as a [`Self::bind`] check input: any
/// fence record naming this registration denies the bundle. This type performs no Kernel transaction itself and never
/// substitutes process presence or a copied record: [`Self::bind`] only joins
/// owner outputs that already name the same registration digest, identity
/// tuple, broker-local epoch, authority epoch, and fence contour, and that
/// still cover the observation instant.
///
/// The consumer is the maintenance policy gate, which lives outside this
/// file and therefore joins by STITCH, never by a faked in-file call: the
/// Governor-side
/// `crates/governor/eliot-maintenance/src/lib.rs::MaintenanceBrokerEvidence`
/// and its `authenticated_session_available` predicate feeding
/// `MaintenanceTriggerInput::user_session_available`, read at
/// `bins/eliotd/src/maintenance_trigger_evaluator.rs` and enforced by
/// `MaintenanceController::evaluate_trigger`. This bundle provisions the
/// broker half of that join; [`Self::authenticated_session_available`]
/// re-validates lease freshness at use time with the same name so the stitch
/// point stays exact. No token, credential, or reusable desktop secret is
/// carried.
#[derive(Clone, Debug)]
pub(crate) struct BrokerMaintenanceEvidence {
    registration: RegistrationReceipt,
    heartbeat_grant: RegistrationGrant,
    launch_grant: LaunchGrant,
}

impl BrokerMaintenanceEvidence {
    /// Joins the four owner observations into one bound bundle.
    ///
    /// The binding equalities mirror the ones the broker owner already
    /// enforces when it seals a registration, refreshes it, authorizes a
    /// launch, or validates a fence receipt: same identity tuple, same
    /// broker-local epoch, same authority epoch, same fence contour, and a
    /// lease that still covers `observed_at`. Any fence record naming this
    /// registration denies the bundle, and a fence naming another digest is
    /// a caller mismatch, never evidence. Every refusal is a typed
    /// [`PortError`]; a forged digest, epoch, fence, or expiry grants
    /// nothing.
    pub(crate) fn bind(
        registration: &RegistrationReceipt,
        heartbeat_grant: &RegistrationGrant,
        launch_grant: &LaunchGrant,
        fence: Option<&RegistrationFenceReceipt>,
        observed_at: u64,
    ) -> Result<Self, PortError> {
        if observed_at == 0 {
            return Err(PortError::Invalid(
                "maintenance broker evidence observation is zero".to_owned(),
            ));
        }
        if registration.status != RegistrationStatus::Active {
            return Err(PortError::Invalid(
                "maintenance broker registration is not active".to_owned(),
            ));
        }
        let heartbeat_request = &heartbeat_grant.registration;
        let same_tuple = heartbeat_request.installation_id == registration.installation_id
            && heartbeat_request.windows_sid == registration.windows_sid
            && heartbeat_request.interactive_session_id == registration.interactive_session_id
            && heartbeat_request.boot_session_id == registration.boot_session_id
            && heartbeat_request.broker_process_id == registration.broker_process_id;
        if !same_tuple
            || heartbeat_grant.user_broker_epoch != registration.user_broker_epoch
            || !heartbeat_grant
                .authority_epoch
                .is_same_authority(&registration.authority_epoch)
            || heartbeat_grant.fence_id != registration.fence_id
        {
            return Err(PortError::Invalid(
                "heartbeat grant does not bind this broker registration".to_owned(),
            ));
        }
        if observed_at >= registration.expires_at || observed_at >= heartbeat_grant.expires_at {
            return Err(PortError::Invalid(
                "broker registration lease is not current".to_owned(),
            ));
        }
        if launch_grant.registration_digest != registration.registration_digest
            || launch_grant.user_broker_epoch != registration.user_broker_epoch
            || !launch_grant
                .authority_epoch
                .is_same_authority(&registration.authority_epoch)
            || launch_grant.fence_id != registration.fence_id
        {
            return Err(PortError::Invalid(
                "launch grant does not bind this broker registration".to_owned(),
            ));
        }
        if observed_at >= launch_grant.expires_at {
            return Err(PortError::Invalid(
                "broker launch grant is not current".to_owned(),
            ));
        }
        if let Some(fence) = fence {
            if fence.registration_digest == registration.registration_digest {
                return Err(PortError::Invalid(
                    "broker registration is fenced".to_owned(),
                ));
            }
            return Err(PortError::Invalid(
                "fence receipt does not bind this broker registration".to_owned(),
            ));
        }
        Ok(Self {
            registration: registration.clone(),
            heartbeat_grant: heartbeat_grant.clone(),
            launch_grant: launch_grant.clone(),
        })
    }

    /// Whether a current authenticated User Broker session is established.
    ///
    /// The bundle only exists after [`Self::bind`] proved the owner join, so
    /// this re-checks what time can invalidate: the sealed lease, the
    /// heartbeat renewal, and the launch grant must all still cover
    /// `observed_at`. A logout, revocation, or expiry between the maintenance
    /// decision and start/resume is therefore caught here instead of being
    /// carried forward as a previously valid decision.
    #[must_use]
    pub(crate) fn authenticated_session_available(&self, observed_at: u64) -> bool {
        self.registration.status == RegistrationStatus::Active
            && observed_at != 0
            && observed_at < self.registration.expires_at
            && observed_at < self.heartbeat_grant.expires_at
            && observed_at < self.launch_grant.expires_at
    }
}

impl AuthorityPort for KernelAuthorityPort {
    fn register(&mut self, request: &RegistrationRequest) -> Result<RegistrationGrant, PortError> {
        let payload =
            serde_json::to_value(request).map_err(|error| PortError::Invalid(error.to_string()))?;
        let identity = self.issue(BrokerOperation::Register, &payload)?;
        serde_json::from_value(kernel_call(
            &self.client,
            REGISTER_OPERATION,
            payload,
            identity,
        )?)
        .map_err(|error| PortError::Invalid(format!("decode registration grant: {error}")))
    }

    fn heartbeat(
        &mut self,
        receipt: &RegistrationReceipt,
        observed_at: u64,
    ) -> Result<RegistrationGrant, PortError> {
        let payload = serde_json::json!({
            "registration": receipt,
            "observed_at": observed_at,
        });
        let identity = self.issue(BrokerOperation::HeartbeatRenewal, &payload)?;
        kernel_call(&self.client, HEARTBEAT_OPERATION, payload, identity).and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode heartbeat grant: {error}")))
        })
    }

    fn authorize_launch(
        &mut self,
        receipt: &RegistrationReceipt,
        request: &LaunchRequest,
    ) -> Result<LaunchGrant, PortError> {
        let payload = serde_json::json!({
            "registration": receipt,
            "request": request,
        });
        let now = now_unix_ms()?;
        let identity = {
            let mut issuer = self.issuer.lock().map_err(|_| PortError::Unknown)?;
            issuer
                .issue_authorize_launch(
                    &request.approved.request_id,
                    &request.approved.idempotency_key,
                    &payload,
                    now,
                )
                .map_err(identity_port_error)?
                .identity
        };
        kernel_call(&self.client, AUTHORIZE_LAUNCH_OPERATION, payload, identity).and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode launch grant: {error}")))
        })
    }

    fn validate_native_resource_selection_current(
        &mut self,
        receipt: &RegistrationReceipt,
        selection: &NativeResourceSelection,
        observed_at: u64,
    ) -> Result<(), PortError> {
        let payload = serde_json::json!({
            "registration": receipt,
            "selection": selection,
            "observed_at": observed_at,
        });
        let identity = self.issue(
            BrokerOperation::ValidateNativeResourceSelectionCurrent,
            &payload,
        )?;
        let response = kernel_call(
            &self.client,
            VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION,
            payload,
            identity,
        )?;
        serde_json::from_value::<()>(response).map_err(|error| {
            PortError::Invalid(format!("decode native resource currentness: {error}"))
        })
    }

    fn fence(
        &mut self,
        request: &RegistrationFenceRequest,
    ) -> Result<RegistrationFenceReceipt, PortError> {
        let payload =
            serde_json::to_value(request).map_err(|error| PortError::Invalid(error.to_string()))?;
        let identity = self.issue(BrokerOperation::FenceLogoff, &payload)?;
        kernel_call(&self.client, FENCE_OPERATION, payload, identity).and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode fence receipt: {error}")))
        })
    }
}
