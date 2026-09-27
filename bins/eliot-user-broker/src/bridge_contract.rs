//! I6.5 bridge contract declaration for the user broker.
//!
//! The user broker translates, isolates and observes between the interactive
//! user session and the Kernel authority service. It is a mechanical facet of
//! a credential/session owner, not a disposable bridge: the broker retains its
//! session/credential responsibilities, and the Kernel retains authority
//! issuance. Task meaning, policy decisions and promotion remain with the
//! Governor and Dreamer owners.
//!
//! The contract is bound to the broker's own protocol version and operation
//! set, not to a mutable README or a self-reported version alone.

use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, ProcessExecutorProfile,
    SideEffect, SuiteRevision, TimeoutsAndCancellation, UpstreamProject, UpstreamVersion,
};

use crate::{PROTOCOL_VERSION, SERVICE_NAME};

/// Builds the user-broker contract from the broker's own protocol version and
/// service identity.
pub fn user_broker_contract() -> Result<BridgeContract, BridgeContractError> {
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new(SERVICE_NAME)?,
        upstream_project_and_license: UpstreamProject {
            name: "ELIOT Kernel".to_owned(),
            license: "ELIOT".to_owned(),
        },
        upstream_version: UpstreamVersion {
            version: PROTOCOL_VERSION.to_owned(),
            artifact: SERVICE_NAME.to_owned(),
        },
        eliot_capabilities: vec![
            BridgeCapability {
                capability: "user.registration".to_owned(),
                protocol_mapping: "register -> kernel.register".to_owned(),
            },
            BridgeCapability {
                capability: "user.heartbeat".to_owned(),
                protocol_mapping: "heartbeat -> kernel.heartbeat".to_owned(),
            },
            BridgeCapability {
                capability: "user.launch-authorization".to_owned(),
                protocol_mapping: "authorize-launch -> kernel.authorize-launch".to_owned(),
            },
            BridgeCapability {
                capability: "user.fencing".to_owned(),
                protocol_mapping: "fence -> kernel.fence".to_owned(),
            },
        ],
        data_classes: vec![
            DataClass::new("user.registration.receipt")?,
            DataClass::new("user.launch.grant")?,
            DataClass::new("user.registration.fence-receipt")?,
        ],
        credentials_boundary: CredentialsBoundary {
            owner: "user-broker.session".to_owned(),
            refs_only: true,
            boundary: "broker-issued registration and launch grants; Kernel-issued authority; no raw credential crosses the broker".to_owned(),
        },
        side_effects: vec![
            SideEffect {
                effect: "user.registration".to_owned(),
                authority: "kernel.register-operation".to_owned(),
            },
            SideEffect {
                effect: "user.launch".to_owned(),
                authority: "kernel.authorize-launch-operation".to_owned(),
            },
            SideEffect {
                effect: "user.fence".to_owned(),
                authority: "kernel.fence-operation".to_owned(),
            },
        ],
        timeouts_and_cancellation: TimeoutsAndCancellation {
            request_timeout_ms: None,
            cancellation: "broker-operation-identity-reuse".to_owned(),
        },
        health_probe: HealthProbe {
            probe: "registration-receipt-readback".to_owned(),
            read_only: true,
        },
        failure_translation: vec![
            FailureTranslation {
                upstream_failure: "kernel.front-door-closed".to_owned(),
                eliot_failure: "broker.unavailable".to_owned(),
                boundary: "no authority issued; retry after re-attachment".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "kernel.unknown-outcome".to_owned(),
                eliot_failure: "broker.unknown-outcome".to_owned(),
                boundary: "unknown outcome preserved; reconcile, never blind retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "kernel.rejected".to_owned(),
                eliot_failure: "broker.invalid".to_owned(),
                boundary: "typed refusal; no semantic decision granted".to_owned(),
            },
        ],
        process_executor_profile: ProcessExecutorProfile {
            executor: "P-03 ProcessExecutor".to_owned(),
            contour: "broker-process-binding".to_owned(),
            single_take: true,
        },
        independent_contract_suite: SuiteRevision {
            suite: "eliot-user-broker".to_owned(),
            revision: "v1".to_owned(),
        },
        fixture_and_golden_corpus: SuiteRevision {
            suite: "eliot-user-broker".to_owned(),
            revision: "v1".to_owned(),
        },
        update_method: eliot_contracts::UpdateMethod {
            method: "staged-generation-cutover".to_owned(),
            compatibility: "protocol-version-and-operation-set-equality".to_owned(),
        },
        export_removal_path: ExportRemovalPath {
            export: "broker-snapshot-and-receipts".to_owned(),
            removal: "fence-new-calls-drain-revoke-route-remove-artifacts".to_owned(),
        },
        owner_resume: "Governor resumes task meaning and policy decisions; Dreamer resumes cognitive assessment and promotion; the broker only translates, isolates and observes authority operations".to_owned(),
    })
}

/// Validates the user-broker contract.
pub fn validate_user_broker_contract(contract: &BridgeContract) -> Result<(), BridgeContractError> {
    contract.validate().map_err(BridgeContractError::Contract)?;
    if contract.bridge_id.as_str() != SERVICE_NAME {
        return Err(BridgeContractError::Binding {
            field: "bridge_id",
            detail: "contract bridge id does not match the broker service name",
        });
    }
    Ok(())
}

/// Typed failure for user-broker contract construction and validation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeContractError {
    /// The neutral contract failed validation.
    #[error("bridge contract invalid: {0}")]
    Contract(#[from] eliot_contracts::ContractError),
    /// The contract does not bind to the broker identity.
    #[error("bridge contract binding failed for {field}: {detail}")]
    Binding {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
}
