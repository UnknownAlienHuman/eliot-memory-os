//! I6.5 bridge contract declaration for the Codex App Server adapter.
//!
//! The Codex adapter translates, isolates and observes between the Codex App
//! Server stdio/JSONL protocol and the provider-neutral A-01 contracts. Task
//! meaning, policy decisions and promotion remain with the Governor and
//! Dreamer owners; the adapter never starts a child, owns canonical state, or
//! treats a provider terminal message as task finish.
//!
//! The contract is bound to the adapter's exact route identity (host family,
//! adapter id, protocol transport), not to a mutable README or a self-reported
//! version alone.

use eliot_agent_api::RouteFingerprint;
use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, ProcessExecutorProfile,
    SideEffect, SuiteRevision, TimeoutsAndCancellation, UpstreamProject, UpstreamVersion,
};

use crate::{
    CODEX_ADAPTER_ID, CODEX_HOST_FAMILY, CODEX_PROTOCOL_TRANSPORT, CODEX_WIRE_SCHEMA_VERSION,
};

/// Builds the Codex adapter contract from the admitted route.
///
/// The route's host family, adapter id, and protocol transport supply the
/// exact upstream identity; the contract is derived from the admitted route,
/// never self-reported.
pub fn codex_adapter_contract(
    route: &RouteFingerprint,
) -> Result<BridgeContract, BridgeContractError> {
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new(CODEX_ADAPTER_ID)?,
        upstream_project_and_license: UpstreamProject {
            name: "Codex App Server".to_owned(),
            license: "OpenAI".to_owned(),
        },
        upstream_version: UpstreamVersion {
            version: CODEX_WIRE_SCHEMA_VERSION.to_owned(),
            artifact: CODEX_ADAPTER_ID.to_owned(),
        },
        eliot_capabilities: vec![
            BridgeCapability {
                capability: "agent.execution".to_owned(),
                protocol_mapping: format!(
                    "{CODEX_HOST_FAMILY}/{CODEX_PROTOCOL_TRANSPORT} -> A-01 agent-result"
                ),
            },
            BridgeCapability {
                capability: "agent.event.normalization".to_owned(),
                protocol_mapping: "jsonl-stream -> normalized-host-event".to_owned(),
            },
            BridgeCapability {
                capability: "agent.cancellation".to_owned(),
                protocol_mapping: "executor.cancel(operation-id)".to_owned(),
            },
        ],
        data_classes: vec![
            DataClass::new("agent.codex.request")?,
            DataClass::new("agent.codex.response")?,
            DataClass::new("agent.candidate.result")?,
            DataClass::new("agent.usage.receipt")?,
        ],
        credentials_boundary: CredentialsBoundary {
            owner: "composition.secret-ref".to_owned(),
            refs_only: true,
            boundary: "credential reference only; never resolved, logged, or forwarded by this package".to_owned(),
        },
        side_effects: vec![SideEffect {
            effect: "agent.codex.launch".to_owned(),
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
                upstream_failure: "codex.route-mismatch".to_owned(),
                eliot_failure: "adapter.route-mismatch".to_owned(),
                boundary: "typed refusal; no task decision granted".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "codex.session-mismatch".to_owned(),
                eliot_failure: "adapter.session-mismatch".to_owned(),
                boundary: "typed refusal; reconcile before retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "codex.partial-output".to_owned(),
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
            suite: "eliot-agent-codex".to_owned(),
            revision: "v1".to_owned(),
        },
        fixture_and_golden_corpus: SuiteRevision {
            suite: "eliot-agent-codex".to_owned(),
            revision: "v1".to_owned(),
        },
        update_method: eliot_contracts::UpdateMethod {
            method: "staged-generation-cutover".to_owned(),
            compatibility: "route-identity-and-wire-schema-equality".to_owned(),
        },
        export_removal_path: ExportRemovalPath {
            export: "candidate-result-and-evidence-refs".to_owned(),
            removal: "fence-new-calls-drain-revoke-route-remove-artifacts".to_owned(),
        },
        owner_resume: "Governor resumes task meaning and policy decisions; Dreamer resumes cognitive assessment and promotion; the adapter only translates, isolates and observes".to_owned(),
    })
}

/// Validates the Codex adapter contract against the admitted route.
///
/// The contract's bridge identity must match the adapter id, and the route
/// must be the exact Codex route. Any mismatch is a contract-binding failure.
pub fn validate_codex_adapter_contract(
    contract: &BridgeContract,
    route: &RouteFingerprint,
) -> Result<(), BridgeContractError> {
    contract.validate().map_err(BridgeContractError::Contract)?;
    if contract.bridge_id.as_str() != CODEX_ADAPTER_ID {
        return Err(BridgeContractError::Binding {
            field: "bridge_id",
            detail: "contract bridge id does not match the Codex adapter id",
        });
    }
    if route.host_family != CODEX_HOST_FAMILY
        || route.adapter != CODEX_ADAPTER_ID
        || route.protocol_transport != CODEX_PROTOCOL_TRANSPORT
    {
        return Err(BridgeContractError::Binding {
            field: "route",
            detail: "route is not the exact Codex App Server route",
        });
    }
    Ok(())
}

/// Typed failure for Codex adapter contract construction and validation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeContractError {
    /// The neutral contract failed validation.
    #[error("bridge contract invalid: {0}")]
    Contract(#[from] eliot_contracts::ContractError),
    /// The contract does not bind to the admitted route.
    #[error("bridge contract binding failed for {field}: {detail}")]
    Binding {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
}
