//! I6.5 bridge contract declaration for the agent bridge.
//!
//! The agent bridge translates, isolates and observes between the
//! agent-facing MCP/stdio protocol and the Kernel named-pipe IPC protocol.
//! Task meaning, policy decisions and promotion remain with the Governor and
//! Dreamer owners; this declaration records the exact boundary where the
//! bridge stops and those owners resume.
//!
//! The contract is bound to the admitted [`AgentBridgeClientDeclaration`]
//! (which carries the immutable `ModuleContract` and `ModuleGeneration`), not
//! to a mutable README or a self-reported version alone. The binding is the
//! declaration's own recomputed content digest
//! ([`AgentBridgeClientDeclaration::compute_digest`],
//! `sha256_hex(canonical_json_bytes(..))` over every declaration field), which
//! [`AgentBridgeClientDeclaration::validate`] already enforces field by field,
//! so a declaration edited after admission cannot present the old contract.

use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, LowercaseSha256,
    ProcessExecutorProfile, SideEffect, SuiteRevision, TimeoutsAndCancellation, UpstreamProject,
    UpstreamVersion,
};
use eliot_protocol::AgentBridgeClientDeclaration;

/// Recomputes the admitted declaration's content digest as the neutral typed
/// digest the contract carries.
///
/// `AgentBridgeClientDeclaration::validate` already recomputes and compares
/// `declaration_sha256`; this is the same value, retyped. A checked copy never
/// reaches the contract because the digest is recomputed from the admitted
/// declaration on every construction and every validation.
fn admitted_declaration_digest(
    declaration: &AgentBridgeClientDeclaration,
) -> Result<LowercaseSha256, BridgeContractError> {
    let hex = declaration
        .compute_digest()
        .map_err(|_| BridgeContractError::Binding {
            field: "admitted_binding_digest",
            detail: "admitted declaration digest could not be recomputed",
        })?;
    serde_json::from_value(serde_json::Value::String(hex)).map_err(|_| {
        BridgeContractError::Binding {
            field: "admitted_binding_digest",
            detail: "admitted declaration digest is not a canonical SHA-256 value",
        }
    })
}

/// Builds the agent-bridge contract from the admitted declaration.
///
/// The declaration's `ModuleContract` and `ModuleGeneration` supply the exact
/// upstream version and artifact, and the recomputed declaration digest binds
/// the admitted artifact/config/generation; the contract is derived from the
/// admitted generation, never self-reported.
pub fn agent_bridge_contract(
    declaration: &AgentBridgeClientDeclaration,
) -> Result<BridgeContract, BridgeContractError> {
    let module_id = declaration.module_id.as_str();
    let artifact = declaration.module_contract.artifact_id.as_str();
    let version = declaration.module_contract.version.to_string();
    let capabilities = declaration
        .capabilities
        .iter()
        .map(|capability| BridgeCapability {
            capability: capability.clone(),
            protocol_mapping: format!("{capability} -> eliot.agent-bridge.v1"),
        })
        .collect();
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new(module_id)?,
        admitted_binding_digest: Some(admitted_declaration_digest(declaration)?),
        upstream_project_and_license: UpstreamProject {
            name: "ELIOT Kernel".to_owned(),
            license: "ELIOT".to_owned(),
        },
        upstream_version: UpstreamVersion {
            version,
            artifact: artifact.to_owned(),
        },
        eliot_capabilities: capabilities,
        data_classes: vec![
            DataClass::new("agent.activation.request")?,
            DataClass::new("agent.activation.receipt")?,
            DataClass::new("agent.event.envelope")?,
            DataClass::new("agent.host.request")?,
            DataClass::new("agent.host.event")?,
        ],
        credentials_boundary: CredentialsBoundary {
            owner: "kernel.session".to_owned(),
            refs_only: true,
            boundary: "Kernel-issued session and capability token; no raw credential crosses the bridge".to_owned(),
        },
        side_effects: vec![
            SideEffect {
                effect: "agent.bridge.activate".to_owned(),
                authority: "kernel.capability-token".to_owned(),
            },
            SideEffect {
                effect: "agent.event.forward".to_owned(),
                authority: "kernel.event-route".to_owned(),
            },
            SideEffect {
                effect: "agent.host.request".to_owned(),
                authority: "kernel.host-request-route".to_owned(),
            },
        ],
        timeouts_and_cancellation: TimeoutsAndCancellation {
            request_timeout_ms: Some(60_000),
            cancellation: "kernel.request-cancellation".to_owned(),
        },
        health_probe: HealthProbe {
            probe: "activation exchange over admitted transport".to_owned(),
            read_only: false,
        },
        failure_translation: vec![
            FailureTranslation {
                upstream_failure: "transport.send-failed".to_owned(),
                eliot_failure: "provider.unavailable".to_owned(),
                boundary: "no phase reached; re-attach and reconcile before retrying".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "transport.unknown-outcome".to_owned(),
                eliot_failure: "provider.unknown-outcome".to_owned(),
                boundary: "unknown outcome preserved; reconcile, never blind retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "kernel.rejected".to_owned(),
                eliot_failure: "provider.rejected".to_owned(),
                boundary: "typed refusal; no task decision granted".to_owned(),
            },
        ],
        process_executor_profile: ProcessExecutorProfile {
            executor: "P-03 ProcessExecutor".to_owned(),
            contour: "single-take launch binding via host".to_owned(),
            single_take: true,
        },
        independent_contract_suite: SuiteRevision {
            suite: "eliot-agent-bridge".to_owned(),
            revision: "v1".to_owned(),
        },
        fixture_and_golden_corpus: SuiteRevision {
            suite: "eliot-agent-bridge".to_owned(),
            revision: "v1".to_owned(),
        },
        update_method: eliot_contracts::UpdateMethod {
            method: "staged-generation-cutover".to_owned(),
            compatibility: "module-contract-and-generation-equality".to_owned(),
        },
        export_removal_path: ExportRemovalPath {
            export: "bridge-journal-and-receipts".to_owned(),
            removal: "fence-new-calls-drain-revoke-route-remove-artifacts".to_owned(),
        },
        owner_resume: "Governor resumes task meaning and policy decisions; Dreamer resumes cognitive assessment and promotion; the bridge only translates, isolates and observes".to_owned(),
    })
}

/// Validates the agent-bridge contract against the admitted declaration.
///
/// The contract's bridge identity must match the declaration's module id, the
/// upstream version/artifact must match the declaration's module contract and
/// generation, and the contract's admitted binding digest must equal the digest
/// recomputed from the admitted declaration. Any mismatch is a
/// contract-binding failure: a well-formed contract for a different admitted
/// declaration is not a pass.
pub fn validate_agent_bridge_contract(
    contract: &BridgeContract,
    declaration: &AgentBridgeClientDeclaration,
) -> Result<(), BridgeContractError> {
    contract.validate().map_err(BridgeContractError::Contract)?;
    if contract.bridge_id.as_str() != declaration.module_id.as_str() {
        return Err(BridgeContractError::Binding {
            field: "bridge_id",
            detail: "contract bridge id does not match the admitted declaration module id",
        });
    }
    if contract.upstream_version.artifact != declaration.module_contract.artifact_id.as_str() {
        return Err(BridgeContractError::Binding {
            field: "upstream_version.artifact",
            detail: "contract artifact does not match the admitted module contract artifact",
        });
    }
    let admitted = admitted_declaration_digest(declaration)?;
    if !contract.binds_admitted_generation(&admitted) {
        return Err(BridgeContractError::Binding {
            field: "admitted_binding_digest",
            detail: "contract does not bind the admitted declaration generation",
        });
    }
    Ok(())
}

/// Typed failure for agent-bridge contract construction and validation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeContractError {
    /// The neutral contract failed validation.
    #[error("bridge contract invalid: {0}")]
    Contract(#[from] eliot_contracts::ContractError),
    /// The contract does not bind to the admitted declaration.
    #[error("bridge contract binding failed for {field}: {detail}")]
    Binding {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
}
