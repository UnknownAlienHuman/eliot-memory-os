//! P-07 Kernel service boundary.
//!
//! This crate composes the Kernel decision core into the long-lived service
//! boundary described by Implementation I1.2-I1.5 and I14.16.  It owns the
//! provider-neutral lifecycle, Host handoff contract, readiness admission and
//! drain/recovery decisions.  Host remains responsible for physical process
//! containment and the platform adapter remains responsible for OS effects.
//!
//! A service is never considered ready because a process exists.  The Host
//! handshake, exact activation identity, process observation, health vector,
//! and supervision evidence must all agree before normal admission opens.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::future::Future;
use std::pin::Pin;

mod lifecycle;
mod protocol;
mod store_client;

pub use eliot_process::ProcessExecutionAdmissionRequest;
pub use lifecycle::{
    AdmissionLease, KernelService, KernelServiceError, KernelServiceState, ServiceFailure,
};
pub use protocol::{
    ContainmentAction, HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot,
    HostKernelCandidateBinding, HostProcessBinding, HostStoreBootstrapRequirement,
    KERNEL_CONTROL_PIPE, KERNEL_CONTROL_WIRE_ID, KERNEL_CONTROL_WIRE_VERSION,
    KernelActivationPermit, KernelActivationQuery, KernelActivationReceipt, KernelControlCommand,
    KernelControlRequest, KernelControlResponse, KernelReadyReceipt,
    ProcessAuthorityHandoffDescriptor, ProcessExecutionRejection, ProcessExecutionRequest,
    ProcessExecutionResponse, ProcessObservation, RestartBudget, StoreBootstrapDescriptor,
    control_request_frame, control_response_frame, decode_control_request_frame,
    decode_control_response_frame,
};
pub use store_client::{EbpCanonicalStoreClient, EbpStoreTransport, StoreClientError};

/// Boxed future for provider-neutral Kernel process operations.
pub type ProcessExecutionFuture<'a> =
    Pin<Box<dyn Future<Output = ProcessExecutionResponse> + Send + 'a>>;

/// Production client/port used by authenticated testd/native callers.
///
/// Implementations exchange only inert request and response projections. A
/// port never receives [`eliot_process::ProcessRequest`] or a dispatch permit.
pub trait ProcessExecutionClient: Send + Sync {
    /// Submits one closed process operation to the Kernel front door.
    fn execute(&self, request: ProcessExecutionRequest) -> ProcessExecutionFuture<'_>;
}

use eliot_contracts::{
    ContractIdentity, ContractVersion, contract_identity as make_contract_identity,
};
use thiserror::Error;

/// Stable wire name for the Kernel service boundary.
pub const CONTRACT_NAME: &str = "eliot.kernel.service";
/// Current wire revision for the Kernel service boundary.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Stable neutral route identity for the canonical Store bridge.
pub const STORE_ROUTE_IDENTITY: &str = "store_bridge";
/// Stable neutral module identity used by the Store EBP contract.
pub const STORE_MODULE_IDENTITY: &str = "eliot-store";

/// Errors produced while deriving the service contract identity.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContractIdentityError {
    /// The canonical contract shape could not be encoded.
    #[error("kernel service contract shape could not be serialized")]
    Serialization,
    /// A foundation contract rejected the identity.
    #[error("foundation contract: {0}")]
    Foundation(#[from] eliot_contracts::ContractError),
}

/// Returns the stable identity used by Host/Kernel protocol handshakes.
pub fn contract_identity() -> Result<ContractIdentity, ContractIdentityError> {
    #[derive(serde::Serialize)]
    struct Shape {
        surface: &'static str,
        version: ContractVersion,
        admission_rule: &'static str,
        handoff_rule: &'static str,
        unknown_rule: &'static str,
    }

    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            surface: "host_handoff_lifecycle_readiness_admission",
            version: CONTRACT_VERSION,
            admission_rule: "ready_requires_exact_handshake_process_health_and_supervision",
            handoff_rule: "candidate_starts_without_authority_and_consumes_one_nonce_once",
            unknown_rule: "unknown_external_state_closes_admission_and_requires_recovery",
        },
    )
    .map_err(ContractIdentityError::Foundation)
}

/// Validates an identity without carrying platform or secret material.
pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if value.trim().is_empty() {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1024 {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}
