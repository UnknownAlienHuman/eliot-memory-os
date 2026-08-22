//! P-05 external Host Supervisor service boundary.
//!
//! Host owns physical lifecycle for the approved Kernel and managed
//! dependencies.  It does not issue authority, inspect project semantics, or
//! infer health from a PID, an open pipe, or an old journal entry.  Platform
//! adapters supply bounded observations/effects through [`ServicePort`], and
//! the host-local operational store receives every accepted process lineage.
//!
//! The service is deliberately small: it serializes start/stop decisions,
//! refuses unknown external outcomes, and requires a validated
//! [`KernelReadyReceipt`] before it advertises an active control contour.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod runtime_control;

mod service;

pub use service::{
    BoundedRestartOutcome, HostDependencyPlan, HostFailure, HostService, HostServiceError,
    HostServiceState, KernelStartReceipt, ServiceStopReceipt,
};

use eliot_contracts::{
    ContractIdentity, ContractVersion, contract_identity as make_contract_identity,
};
use thiserror::Error;

/// Stable wire name for the external Host Supervisor boundary.
pub const CONTRACT_NAME: &str = "eliot.kernel.host-service";
/// Current wire revision for the Host Supervisor boundary.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Errors produced while deriving the Host service contract identity.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContractIdentityError {
    /// A foundation contract rejected the identity.
    #[error("foundation contract: {0}")]
    Foundation(#[from] eliot_contracts::ContractError),
}

/// Returns the stable identity used by Host protocol and deployment handshakes.
pub fn contract_identity() -> Result<ContractIdentity, ContractIdentityError> {
    #[derive(serde::Serialize)]
    struct Shape {
        surface: &'static str,
        version: ContractVersion,
        ownership: &'static str,
        unknown_rule: &'static str,
    }

    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            surface: "host_process_lifecycle_activation_recovery",
            version: CONTRACT_VERSION,
            ownership: "host_controls_approved_processes_and_records_observed_lineage",
            unknown_rule: "unknown_or_incomplete_effect_closes_activation_and_requires_recovery",
        },
    )
    .map_err(ContractIdentityError::Foundation)
}
