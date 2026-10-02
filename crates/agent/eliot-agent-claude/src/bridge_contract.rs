//! I6.5 bridge contract declaration for the Claude sidecar adapter.
//!
//! The Claude adapter translates, isolates and observes between the Claude
//! Agent SDK NDJSON sidecar protocol and the provider-neutral A-01 contracts.
//! Task meaning, policy decisions and promotion remain with the Governor and
//! Dreamer owners; the adapter produces candidate-only results and never
//! acquires task authority.
//!
//! The contract is bound to the admitted [`ClaudeAdapterDescriptor`] (adapter
//! id, factory revision, and exact route) plus the route owner's own
//! fingerprint digest for that admitted route
//! ([`eliot_agent_api::route_fingerprint_digest_for`]), not to a mutable README
//! or a self-reported version alone.
//!
//! ## Named ceiling: no owner-issued declaration is presented at this layer
//!
//! The only consumer of this module is [`crate::execution::prepare`]. It
//! DERIVES the declaration from `(&input.descriptor, &input.admitted.route)`
//! and validates it against that same pair, so every binding check inside
//! [`validate_claude_adapter_contract`] is already implied by checks that ran
//! earlier on the admit path:
//!
//! - [`crate::execution::validate_claude_route`] and
//!   [`crate::execution::validate_binding_for_claude`] fix the bound route to
//!   the Claude sidecar route;
//! - `validate_execution_binding` calls
//!   `ProviderExecutionBinding::validate_against_attempt`, which proves
//!   `input.admitted.route == input.binding.route`;
//! - [`crate::execution::ClaudeAdapterDescriptor::validate_for`] proves
//!   `input.descriptor.route == input.binding.route` and that the adapter id
//!   and factory revision are current.
//!
//! Deleting the `validate_claude_adapter_contract` call in `prepare` therefore
//! changes no outcome. This module is therefore NOT an admission gate and
//! claims no rejection of a declaration presented for another route
//! generation.
//!
//! What the call does check is real but narrower: [`BridgeContract::validate`]
//! over the fourteen declared-metadata field groups that construction does not
//! itself validate, and the owner-digest recomputation. Those are
//! declaration-completeness and constant-regression refusals. They are kept
//! because the issue requires an unknown required metadata item to remain a
//! qualification gap rather than be filled in, and because the refusal is
//! typed and lands before any operation identity, credential or task decision
//! exists.
//!
//! The missing owner is a bridge-declaration issuer: a composition or registry
//! owner (the #874 native-worker adapter registry, or a versioned deployment
//! declaration loaded the way `eliot-agent-bridge` loads
//! `AgentBridgeClientDeclaration`) that holds this `BridgeContract` as
//! independently versioned, artifact/config/route-generation-bound data and
//! presents it to `prepare` as an input. Until that owner exists, the I6.5
//! declaration cannot be authoritatively checked in this crate. No generation,
//! fence, epoch, capability or owner-signed handle is invented here to stand in
//! for it, and no validation in this module or in `prepare` was weakened to
//! reach this conclusion.

use eliot_agent_api::{RouteFingerprint, route_fingerprint_digest_for};
use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, LowercaseSha256,
    ProcessExecutorProfile, SideEffect, SuiteRevision, TimeoutsAndCancellation, UpstreamProject,
    UpstreamVersion,
};

use crate::execution::{CLAUDE_SIDECAR_FACTORY_REVISION, ClaudeAdapterDescriptor};
use crate::{
    CLAUDE_SIDECAR_ADAPTER_ID, CLAUDE_SIDECAR_HOST_FAMILY, CLAUDE_SIDECAR_PROTOCOL_VERSION,
    CLAUDE_SIDECAR_TRANSPORT,
};

/// Builds the Claude adapter contract from the admitted descriptor and route.
///
/// The descriptor's adapter id, factory revision, and route supply the exact
/// upstream identity, and the route's owner digest binds the admitted route
/// generation into the contract; the contract is derived from the admitted
/// descriptor, never self-reported.
pub fn claude_adapter_contract(
    descriptor: &ClaudeAdapterDescriptor,
    route: &RouteFingerprint,
) -> Result<BridgeContract, BridgeContractError> {
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new(descriptor.adapter_id.as_str())?,
        admitted_binding_digest: Some(admitted_route_digest(route)?),
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

/// Validates the Claude adapter declaration against the descriptor and route it
/// was derived from.
///
/// For any caller presenting an arbitrary triple this is exact: the bridge id
/// must equal the descriptor adapter id, the descriptor must carry the current
/// Claude adapter id and factory revision, the descriptor route must equal the
/// presented route, and the declared admitted binding digest must equal the
/// route owner's digest recomputed over that exact route.
///
/// For the one in-repo caller, [`crate::execution::prepare`], the binding
/// branches are implied rather than load-bearing. `prepare` derives the
/// declaration from this same `(descriptor, route)` pair, and
/// [`crate::execution::validate_claude_route`],
/// `validate_execution_binding` and
/// [`crate::execution::ClaudeAdapterDescriptor::validate_for`] have already
/// proved those three values mutually equal and current. What remains genuinely
/// capable of refusing here is
/// [`eliot_contracts::BridgeContract::validate`] over the declared metadata
/// that construction does not itself check, plus the owner-digest
/// recomputation. It cannot refuse a declaration presented for another route
/// generation, because no such declaration is presented: see the named ceiling
/// in the module documentation.
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
/// a self-reported label, and so construction and validation recompute it the
/// same way.
fn admitted_route_digest(route: &RouteFingerprint) -> Result<LowercaseSha256, BridgeContractError> {
    route_fingerprint_digest_for(route).map_err(|error| BridgeContractError::Route {
        detail: error.to_string(),
    })
}

/// Typed failure for Claude adapter contract construction and validation.
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
    /// The contract does not bind to the admitted descriptor and route.
    #[error("bridge contract binding failed for {field}: {detail}")]
    Binding {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
}
