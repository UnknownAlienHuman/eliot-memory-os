//! Mechanical wire translation/transport of Kernel-issued authority for the
//! User Broker ↔ Kernel authenticated boundary (B.8 Kernel ↔ User Broker).
//!
//! Architecture anchors: A12.2 Principal, Session и visibility, A12.3 Один
//! governed write path, A13.2 Kernel и failure domains (bounded A12 Security
//! and A13 Resilience). Implementation anchors: I1.3 Optional и on-demand
//! processes, B.1 Kernel ↔ Daemon, P.3 Kernel control boundary, and I2.23
//! Capability-family topology and crate extraction decisions.
//!
//! This module is a thin transport: it forwards `AuthorityPort` calls over
//! `SharedKernelClient::transact_json` and maps `KernelClientError` to
//! `PortError` without retry, cache, default, lease/token minting, semantic
//! decision, or canonical state ownership. All authority remains Kernel-issued.

use serde_json::Value;

use eliot_user_broker_core::{
    AuthorityPort, LaunchGrant, LaunchRequest, PortError, RegistrationFenceReceipt,
    RegistrationFenceRequest, RegistrationGrant, RegistrationReceipt, RegistrationRequest,
};

use super::SharedKernelClient;

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

fn kernel_call(
    client: &SharedKernelClient,
    operation: &str,
    payload: Value,
) -> Result<Value, PortError> {
    let mut client = client.lock().map_err(|_| PortError::Unknown)?;
    client
        .transact_json(operation, payload)
        .map_err(kernel_port_error)
}

pub(crate) struct KernelAuthorityPort {
    pub(crate) client: SharedKernelClient,
}

impl AuthorityPort for KernelAuthorityPort {
    fn register(&mut self, request: &RegistrationRequest) -> Result<RegistrationGrant, PortError> {
        serde_json::from_value(kernel_call(
            &self.client,
            "eliot.user-broker.register",
            serde_json::to_value(request).map_err(|error| PortError::Invalid(error.to_string()))?,
        )?)
        .map_err(|error| PortError::Invalid(format!("decode registration grant: {error}")))
    }

    fn heartbeat(
        &mut self,
        receipt: &RegistrationReceipt,
        observed_at: u64,
    ) -> Result<RegistrationGrant, PortError> {
        kernel_call(
            &self.client,
            "eliot.user-broker.heartbeat",
            serde_json::json!({
                "registration": receipt,
                "observed_at": observed_at,
            }),
        )
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode heartbeat grant: {error}")))
        })
    }

    fn authorize_launch(
        &mut self,
        receipt: &RegistrationReceipt,
        request: &LaunchRequest,
    ) -> Result<LaunchGrant, PortError> {
        kernel_call(
            &self.client,
            "eliot.user-broker.authorize-launch",
            serde_json::json!({
                "registration": receipt,
                "request": request,
            }),
        )
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode launch grant: {error}")))
        })
    }

    fn fence(
        &mut self,
        request: &RegistrationFenceRequest,
    ) -> Result<RegistrationFenceReceipt, PortError> {
        kernel_call(
            &self.client,
            "eliot.user-broker.fence",
            serde_json::to_value(request).map_err(|error| PortError::Invalid(error.to_string()))?,
        )
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| PortError::Invalid(format!("decode fence receipt: {error}")))
        })
    }
}
