//! I6.5 bridge contract declaration for the Claude sidecar adapter.
//!
//! The Claude adapter translates, isolates and observes between the Claude
//! Agent SDK NDJSON sidecar protocol and the provider-neutral A-01 contracts.
//! Task meaning, policy decisions and promotion remain with the Governor and
//! Dreamer owners; the adapter produces candidate-only results and never
//! acquires task authority.
//!
//! The contract is bound to the admitted [`ClaudeAdapterDescriptor`] (adapter
//! id, factory revision, and exact route), not to a mutable README or a
//! self-reported version alone.

use eliot_agent_api::RouteFingerprint;
use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, ProcessExecutorProfile,
    SideEffect, SuiteRevision, TimeoutsAndCancellation, UpstreamProject, UpstreamVersion,
};

use crate::execution::{
    CLAUDE_SIDECAR_ADAPTER_ID, CLAUDE_SIDECAR_FACTORY_REVISION, CLAUDE_SIDECAR_HOST_FAMILY,
    CLAUDE_SIDECAR_PROTOCOL_VERSION, CLAUDE_SIDECAR_TRANSPORT, ClaudeAdapterDescriptor,
};

/// Builds the Claude adapter contract from the admitted descriptor and route.
///
/// The descriptor's adapter id, factory revision, and route supply the exact
/// upstream identity; the contract is derived from the admitted descriptor,
/// never self-reported.
pub fn claude_adapter_contract(
    descriptor: &ClaudeAdapterDescriptor,
    route: &RouteFingerprint,
) -> Result<BridgeContract, BridgeContractError> {
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new(descriptor.adapter_id.as_str())?,
        upstream_project_and_license: UpstreamProject {
            name: "Claude Agent SDK".to_owned(),
            license: "Anthropic".to_owned(),
        },
        upstream_version: UpstreamVersion {
            version: CLAUDE_SIDECAR_PROTOCOL_VERSION.to_owned(),
            artifact: descriptor.adapter_id.as_str().to_owned(),
        },
        eliot_capabilities: vec![
            BridgeCapability {
                capability: "agent.execution".to_owned(),
                protocol_mapping: format!(
                    "{CLAUDE_SIDECAR_HOST_FAMILY}/{CLAUDE_SIDECAR_TRANSPORT} -> A-01 agent-result"
                ),
            },
            BridgeCapability {
                capability: "agent.event.normalization".to_owned(),
                protocol_mapping: "ndjson-stream -> normalized-host-event".to_owned(),
            },
            BridgeCapability {
                capability: "agent.cancellation".to_owned(),
                protocol_mapping: "executor.cancel(operation-id)".to_owned(),
            },
        ],
        data_classes: vec![
            DataClass::new("agent.sidecar.request")?,
            DataClass::new("agent.sidecar.response")?,
            DataClass::new("agent.candidate.result")?,
            DataClass::new("agent.usage.receipt")?,
        ],
        credentials_boundary: CredentialsBoundary {
            owner: "composition.secret-ref".to_owned(),
            refs_only: true,
            boundary: "credential SecretRef reference only; never resolved, logged, or forwarded by this package".to_owned(),
        },
        side_effects: vec![SideEffect {
            effect: "agent.sidecar.launch".to_owned(),
            authority: "P-03 ProcessExecutor".to_owned(),
        }],
        timeouts_and_cancellation: TimeoutsAndCancellation {
            request_timeout_ms: None,
            cancellation: "executor.cancel(operation-id) with cleanup-state".to_owned(),
        },
        health_probe: HealthProbe {
            probe: "executor.inspect(operation-id)".to_owned(),
            read_only: true,
        },
        failure_translation: vec![
            FailureTranslation {
                upstream_failure: "executor.not-found".to_owned(),
                eliot_failure: "adapter.operation-not-found".to_owned(),
                boundary: "typed refusal; no task decision granted".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "executor.unavailable".to_owned(),
                eliot_failure: "adapter.executor-unavailable".to_owned(),
                boundary: "typed refusal; reconcile before retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "executor.unknown-outcome".to_owned(),
                eliot_failure: "adapter.unknown-outcome-requires-reconcile".to_owned(),
                boundary: "unknown outcome preserved; reconcile, never blind retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "sidecar.deadline-exceeded".to_owned(),
                eliot_failure: "adapter.deadline-exceeded".to_owned(),
                boundary: "deadline enforced; cancel and reconcile".to_owned(),
            },
        ],
        process_executor_profile: ProcessExecutorProfile {
            executor: "P-03 ProcessExecutor".to_owned(),
            contour: "single-take launch binding".to_owned(),
            single_take: true,
        },
        independent_contract_suite: SuiteRevision {
            suite: "eliot-agent-claude".to_owned(),
            revision: format!("factory-{CLAUDE_SIDECAR_FACTORY_REVISION}"),
        },
        fixture_and_golden_corpus: SuiteRevision {
            suite: "eliot-agent-claude".to_owned(),
            revision: format!("factory-{CLAUDE_SIDECAR_FACTORY_REVISION}"),
        },
        update_method: eliot_contracts::UpdateMethod {
            method: "staged-generation-cutover".to_owned(),
            compatibility: "descriptor-revision-and-route-equality".to_owned(),
        },
        export_removal_path: ExportRemovalPath {
            export: "candidate-result-and-evidence-refs".to_owned(),
            removal: "fence-new-calls-drain-revoke-route-remove-artifacts".to_owned(),
        },
        owner_resume: "Governor resumes task meaning and policy decisions; Dreamer resumes cognitive assessment and promotion; the adapter only translates, isolates and observes and produces candidate-only results".to_owned(),
    })
}

/// Validates the Claude adapter contract against the admitted descriptor and
/// route.
///
/// The contract's bridge identity must match the descriptor's adapter id, and
/// the descriptor must be the current factory revision for the exact route.
/// Any mismatch is a contract-binding failure.
pub fn validate_claude_adapter_contract(
    contract: &BridgeContract,
    descriptor: &ClaudeAdapterDescriptor,
    route: &RouteFingerprint,
) -> Result<(), BridgeContractError> {
    contract.validate().map_err(BridgeContractError::Contract)?;
    if contract.bridge_id.as_str() != descriptor.adapter_id.as_str() {
        return Err(BridgeContractError::Binding {
            field: "bridge_id",
            detail: "contract bridge id does not match the descriptor adapter id",
        });
    }
    if descriptor.adapter_id != CLAUDE_SIDECAR_ADAPTER_ID {
        return Err(BridgeContractError::Binding {
            field: "adapter_id",
            detail: "descriptor adapter id is not the Claude sidecar adapter",
        });
    }
    if descriptor.factory_revision != CLAUDE_SIDECAR_FACTORY_REVISION {
        return Err(BridgeContractError::Binding {
            field: "factory_revision",
            detail: "descriptor factory revision is stale",
        });
    }
    if &descriptor.route != route {
        return Err(BridgeContractError::Binding {
            field: "route",
            detail: "descriptor route differs from the admitted route",
        });
    }
    Ok(())
}

/// Typed failure for Claude adapter contract construction and validation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeContractError {
    /// The neutral contract failed validation.
    #[error("bridge contract invalid: {0}")]
    Contract(#[from] eliot_contracts::ContractError),
    /// The contract does not bind to the admitted descriptor.
    #[error("bridge contract binding failed for {field}: {detail}")]
    Binding {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
}
