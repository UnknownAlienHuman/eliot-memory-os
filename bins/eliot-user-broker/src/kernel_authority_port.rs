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
use eliot_user_broker_core::{
    AuthorityPort, LaunchGrant, LaunchRequest, PortError, RegistrationFenceReceipt,
    RegistrationFenceRequest, RegistrationGrant, RegistrationReceipt, RegistrationRequest,
};

use super::SharedKernelClient;
use crate::operation_identity::{
    AUTHORIZE_LAUNCH_OPERATION, BrokerOperation, FENCE_OPERATION, HEARTBEAT_OPERATION,
    IssuerHandle, OperationIdentityError, REGISTER_OPERATION,
};

fn kernel_port_error(error: eliot_cli::kernel_client::KernelClientError) -> PortError {
    match error {
        eliot_cli::kernel_client::KernelClientError::FrontDoorClosed(_) => PortError::Unavailable,
        eliot_cli::kernel_client::KernelClientError::UnknownOutcome(_) => PortError::Unknown,
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
