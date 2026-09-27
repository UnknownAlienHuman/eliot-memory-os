//! I6.5 bridge contract declaration for the `OpenCode` HTTP/SSE adapter.
//!
//! The `OpenCode` adapter translates, isolates and observes between the
//! `OpenCode` HTTP/SSE protocol and the provider-neutral A-01 contracts. Task
//! meaning, policy decisions and promotion remain with the Governor and
//! Dreamer owners; the adapter never starts a child, owns canonical state, or
//! treats a provider terminal message as task finish.
//!
//! The contract is bound to the admitted route generation through the route
//! owner's own fingerprint digest
//! ([`eliot_agent_api::route_fingerprint_digest_for`]), not to a mutable
//! README or a self-reported version alone.
//! `validate_opencode_adapter_contract` recomputes that digest from the route
//! it validates against and refuses a contract built for a different route.

use eliot_agent_api::{RouteFingerprint, route_fingerprint_digest_for};
use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, LowercaseSha256,
    ProcessExecutorProfile, SideEffect, SuiteRevision, TimeoutsAndCancellation, UpstreamProject,
    UpstreamVersion,
};

use crate::{OPENCODE_ADAPTER_ID, OPENCODE_HOST_FAMILY, OPENCODE_PROTOCOL_TRANSPORT};

/// Builds the `OpenCode` adapter contract from the admitted route.
///
/// The route's host family, adapter id, and protocol transport supply the
/// exact upstream identity, and the route's owner digest binds the admitted
/// route generation into the contract; the contract is derived from the
/// admitted route, never self-reported.
pub fn opencode_adapter_contract(
    route: &RouteFingerprint,
) -> Result<BridgeContract, BridgeContractError> {
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new(OPENCODE_ADAPTER_ID)?,
        admitted_binding_digest: Some(admitted_route_digest(route)?),
        upstream_project_and_license: UpstreamProject {
            name: "OpenCode".to_owned(),
            license: "OpenCode".to_owned(),
        },
        upstream_version: UpstreamVersion {
            version: "http+sse/v1".to_owned(),
            artifact: OPENCODE_ADAPTER_ID.to_owned(),
        },
        eliot_capabilities: vec![
            BridgeCapability {
                capability: "agent.execution".to_owned(),
                protocol_mapping: format!(
                    "{OPENCODE_HOST_FAMILY}/{OPENCODE_PROTOCOL_TRANSPORT} -> A-01 agent-result"
                ),
            },
            BridgeCapability {
                capability: "agent.event.normalization".to_owned(),
                protocol_mapping: "sse-stream -> normalized-host-event".to_owned(),
            },
            BridgeCapability {
                capability: "agent.cancellation".to_owned(),
                protocol_mapping: "executor.cancel(operation-id)".to_owned(),
            },
        ],
        data_classes: vec![
            DataClass::new("agent.opencode.request")?,
            DataClass::new("agent.opencode.response")?,
            DataClass::new("agent.candidate.result")?,
            DataClass::new("agent.usage.receipt")?,
        ],
        credentials_boundary: CredentialsBoundary {
            owner: "composition.secret-ref".to_owned(),
            refs_only: true,
            boundary: "credential reference only; never resolved, logged, or forwarded by this package".to_owned(),
        },
        side_effects: vec![SideEffect {
            effect: "agent.opencode.launch".to_owned(),
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
                upstream_failure: "opencode.route-mismatch".to_owned(),
                eliot_failure: "adapter.route-mismatch".to_owned(),
                boundary: "typed refusal; no task decision granted".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "opencode.run-error".to_owned(),
                eliot_failure: "adapter.run-error".to_owned(),
                boundary: "typed refusal; reconcile before retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "opencode.unknown-outcome".to_owned(),
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
            suite: "eliot-agent-opencode".to_owned(),
            revision: "v1".to_owned(),
        },
        fixture_and_golden_corpus: SuiteRevision {
            suite: "eliot-agent-opencode".to_owned(),
            revision: "v1".to_owned(),
        },
        update_method: eliot_contracts::UpdateMethod {
            method: "staged-generation-cutover".to_owned(),
            compatibility: "route-identity-and-protocol-equality".to_owned(),
        },
        export_removal_path: ExportRemovalPath {
            export: "candidate-result-and-evidence-refs".to_owned(),
            removal: "fence-new-calls-drain-revoke-route-remove-artifacts".to_owned(),
        },
        owner_resume: "Governor resumes task meaning and policy decisions; Dreamer resumes cognitive assessment and promotion; the adapter only translates, isolates and observes".to_owned(),
    })
}

/// Validates the `OpenCode` adapter contract against the admitted route.
///
/// The contract's bridge identity must match the adapter id, the route must
/// be the exact `OpenCode` route, and the contract's admitted binding digest
/// must equal the digest recomputed from that exact route. A well-formed
/// contract for a different route is a binding failure, not a pass.
pub fn validate_opencode_adapter_contract(
    contract: &BridgeContract,
    route: &RouteFingerprint,
) -> Result<(), BridgeContractError> {
    contract.validate().map_err(BridgeContractError::Contract)?;
    if contract.bridge_id.as_str() != OPENCODE_ADAPTER_ID {
        return Err(BridgeContractError::Binding {
            field: "bridge_id",
            detail: "contract bridge id does not match the OpenCode adapter id",
        });
    }
    if route.host_family != OPENCODE_HOST_FAMILY
        || route.adapter != OPENCODE_ADAPTER_ID
        || route.protocol_transport != OPENCODE_PROTOCOL_TRANSPORT
    {
        return Err(BridgeContractError::Binding {
            field: "route",
            detail: "route is not the exact OpenCode HTTP/SSE route",
        });
    }
    let admitted = admitted_route_digest(route)?;
    if !contract.binds_admitted_generation(&admitted) {
        return Err(BridgeContractError::Binding {
            field: "admitted_binding_digest",
            detail: "contract does not bind the admitted route generation",
        });
    }
    Ok(())
}

/// Recomputes the admitted route's owner digest.
///
/// Reuses the route owner's existing identity function
/// ([`route_fingerprint_digest_for`], `sha256_hex(canonical_json_bytes(..))`
/// over the complete [`RouteFingerprint`]) so the value cannot be free text or
/// a self-reported label, and so the bootstrap gate and every validator
/// recompute it the same way.
fn admitted_route_digest(route: &RouteFingerprint) -> Result<LowercaseSha256, BridgeContractError> {
    route_fingerprint_digest_for(route).map_err(|error| BridgeContractError::Route {
        detail: error.to_string(),
    })
}

/// Typed failure for `OpenCode` adapter contract construction and validation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeContractError {
    /// The neutral contract failed validation.
    #[error("bridge contract invalid: {0}")]
    Contract(#[from] eliot_contracts::ContractError),
    /// The admitted route identity could not be recomputed.
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
