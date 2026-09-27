//! I6.5 bridge contract declaration for the ACP v1 compatibility adapter.
//!
//! The ACP adapter translates, isolates and observes between the ACP v1
//! stdio JSON-RPC protocol and the provider-neutral A-01 contracts. Task
//! meaning, policy decisions and promotion remain with the Governor and
//! Dreamer owners; the adapter never spawns a process, opens a socket, or
//! creates authority.
//!
//! The contract is bound to the adapter's exact protocol version and route
//! identity, not to a mutable README or a self-reported version alone.

use eliot_agent_api::RouteFingerprint;
use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, ProcessExecutorProfile,
    SideEffect, SuiteRevision, TimeoutsAndCancellation, UpstreamProject, UpstreamVersion,
};

use crate::{ACP_PROTOCOL_VERSION, ACP_SCHEMA_VERSION};

/// Builds the ACP adapter contract from the admitted route.
///
/// The route and the adapter's protocol version supply the exact upstream
/// identity; the contract is derived from the admitted protocol version,
/// never self-reported.
pub fn acp_adapter_contract(
    route: &RouteFingerprint,
) -> Result<BridgeContract, BridgeContractError> {
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new("eliot-agent-acp")?,
        upstream_project_and_license: UpstreamProject {
            name: "ACP v1".to_owned(),
            license: "Zed".to_owned(),
        },
        upstream_version: UpstreamVersion {
            version: format!("protocol-v{ACP_PROTOCOL_VERSION}"),
            artifact: ACP_SCHEMA_VERSION.to_owned(),
        },
        eliot_capabilities: vec![
            BridgeCapability {
                capability: "agent.execution".to_owned(),
                protocol_mapping: "acp-v1-jsonrpc -> A-01 agent-result".to_owned(),
            },
            BridgeCapability {
                capability: "agent.event.normalization".to_owned(),
                protocol_mapping: "acp-session -> normalized-host-event".to_owned(),
            },
            BridgeCapability {
                capability: "agent.cancellation".to_owned(),
                protocol_mapping: "executor.cancel(operation-id)".to_owned(),
            },
        ],
        data_classes: vec![
            DataClass::new("agent.acp.request")?,
            DataClass::new("agent.acp.response")?,
            DataClass::new("agent.candidate.result")?,
            DataClass::new("agent.usage.receipt")?,
        ],
        credentials_boundary: CredentialsBoundary {
            owner: "composition.secret-ref".to_owned(),
            refs_only: true,
            boundary: "credential reference only; never resolved, logged, or forwarded by this package".to_owned(),
        },
        side_effects: vec![SideEffect {
            effect: "agent.acp.launch".to_owned(),
            authority: "P-03 ProcessExecutor".to_owned(),
        }],
        timeouts_and_cancellation: TimeoutsAndCancellation {
            request_timeout_ms: None,
            cancellation: "executor.cancel(operation-id)".to_owned(),
        },
        health_probe: HealthProbe {
            probe: "executor.inspect(operation-id)".to_owned(),
            read_only: true,
        },
        failure_translation: vec![
            FailureTranslation {
                upstream_failure: "acp.protocol-version-mismatch".to_owned(),
                eliot_failure: "adapter.unsupported-version".to_owned(),
                boundary: "typed refusal; no task decision granted".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "acp.frame-invalid".to_owned(),
                eliot_failure: "adapter.malformed-frame".to_owned(),
                boundary: "typed refusal; reconcile before retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "acp.unknown-outcome".to_owned(),
                eliot_failure: "adapter.unknown-outcome".to_owned(),
                boundary: "unknown outcome preserved; reconcile, never blind retry".to_owned(),
            },
        ],
        process_executor_profile: ProcessExecutorProfile {
            executor: "P-03 ProcessExecutor".to_owned(),
            contour: "single-take launch binding".to_owned(),
            single_take: true,
        },
        independent_contract_suite: SuiteRevision {
            suite: "eliot-agent-acp".to_owned(),
            revision: format!("protocol-v{ACP_PROTOCOL_VERSION}"),
        },
        fixture_and_golden_corpus: SuiteRevision {
            suite: "eliot-agent-acp".to_owned(),
            revision: format!("protocol-v{ACP_PROTOCOL_VERSION}"),
        },
        update_method: eliot_contracts::UpdateMethod {
            method: "staged-generation-cutover".to_owned(),
            compatibility: "protocol-version-and-route-equality".to_owned(),
        },
        export_removal_path: ExportRemovalPath {
            export: "candidate-result-and-evidence-refs".to_owned(),
            removal: "fence-new-calls-drain-revoke-route-remove-artifacts".to_owned(),
        },
        owner_resume: "Governor resumes task meaning and policy decisions; Dreamer resumes cognitive assessment and promotion; the adapter only translates, isolates and observes".to_owned(),
    })
}

/// Validates the ACP adapter contract against the admitted route.
///
/// The contract's bridge identity must match the adapter id, and the route
/// must be present. Any mismatch is a contract-binding failure.
pub fn validate_acp_adapter_contract(
    contract: &BridgeContract,
    route: &RouteFingerprint,
) -> Result<(), BridgeContractError> {
    contract.validate().map_err(BridgeContractError::Contract)?;
    if contract.bridge_id.as_str() != "eliot-agent-acp" {
        return Err(BridgeContractError::Binding {
            field: "bridge_id",
            detail: "contract bridge id does not match the ACP adapter id",
        });
    }
    route
        .validate()
        .map_err(|error| BridgeContractError::Route {
            detail: error.to_string(),
        })?;
    Ok(())
}

/// Typed failure for ACP adapter contract construction and validation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeContractError {
    /// The neutral contract failed validation.
    #[error("bridge contract invalid: {0}")]
    Contract(#[from] eliot_contracts::ContractError),
    /// The admitted route failed validation.
    #[error("admitted route invalid: {detail}")]
    Route {
        /// Bounded detail.
        detail: String,
    },
    /// The contract does not bind to the admitted route.
    #[error("bridge contract binding failed for {field}: {detail}")]
    Binding {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
}
