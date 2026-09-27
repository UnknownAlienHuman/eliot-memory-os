//! Generation-readiness gate over the immutable module contract and its
//! resolved required-capability graph.
//!
//! This module is the Kernel generation/compatibility owner's consumption
//! point for the completed I6.4 contract. It validates the exact contract
//! surface (every mandatory field) and reads the module's resolved required
//! edges and degraded capabilities from the graph. It manufactures no health,
//! freshness, test success or activation authority: a valid contract over an
//! acyclic resolved graph is necessary but not sufficient for `READY`, and a
//! `READY` generation is still not `ACTIVE` routing or effect authority.

use std::collections::BTreeMap;

use eliot_contracts::ContractId;
use eliot_runtime_contracts::{
    ModuleContract, RequiredCapabilityEdge, RequiredCapabilityGraph, UnresolvedCapability,
    resolve_required_capability_graph,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::KernelResult;

/// Readiness of one module generation before it may reach `READY`.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GenerationReadiness {
    /// The exact contract validates and every required capability is resolved.
    Ready,
    /// A mandatory contract field is missing or a required capability is unresolved.
    Incomplete,
}

/// One module's readiness projection consumed from the contract and the graph.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationReadinessProjection {
    /// Module the projection is for.
    pub module_id: ContractId,
    /// Readiness verdict for this module.
    pub readiness: GenerationReadiness,
    /// Required edges resolved for this module in the graph.
    pub resolved_required: Vec<RequiredCapabilityEdge>,
    /// Optional/advisory capabilities with no resolved provider.
    pub degraded_capabilities: Vec<UnresolvedCapability>,
    /// Blocking reason when [`GenerationReadiness::Incomplete`].
    pub blocking_reason: Option<String>,
}

impl GenerationReadinessProjection {
    fn ready(
        module_id: ContractId,
        resolved_required: Vec<RequiredCapabilityEdge>,
        degraded_capabilities: Vec<UnresolvedCapability>,
    ) -> Self {
        Self {
            module_id,
            readiness: GenerationReadiness::Ready,
            resolved_required,
            degraded_capabilities,
            blocking_reason: None,
        }
    }

    fn incomplete(module_id: ContractId, reason: impl Into<String>) -> Self {
        Self {
            module_id,
            readiness: GenerationReadiness::Incomplete,
            resolved_required: Vec::new(),
            degraded_capabilities: Vec::new(),
            blocking_reason: Some(reason.into()),
        }
    }
}

/// Evaluates generation readiness for one module against the resolved graph.
///
/// The exact completed contract is validated first: a missing mandatory field
/// makes the generation [`GenerationReadiness::Incomplete`] with the typed
/// contract error as the blocking reason. Every required capability must be
/// resolved in the graph; an unresolved required capability blocks readiness
/// with the exact consumer and capability. Degraded optional/advisory
/// capabilities are reported but never block. The projection carries no
/// health, freshness or activation authority.
pub fn evaluate_generation_readiness(
    contract: &ModuleContract,
    graph: &RequiredCapabilityGraph,
) -> GenerationReadinessProjection {
    if let Err(error) = contract.validate() {
        return GenerationReadinessProjection::incomplete(
            contract.module_id.clone(),
            format!("module contract rejected: {error}"),
        );
    }

    let resolved = graph.edges_for(&contract.module_id);
    let missing: Vec<String> = contract
        .required_capabilities
        .iter()
        .filter(|capability| !resolved.iter().any(|edge| edge.capability == **capability))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return GenerationReadinessProjection::incomplete(
            contract.module_id.clone(),
            format!("required capabilities unresolved: {}", missing.join(", ")),
        );
    }

    let degraded = graph.degraded_for(&contract.module_id);
    GenerationReadinessProjection::ready(contract.module_id.clone(), resolved, degraded)
}

/// Resolves the graph over a module set and evaluates readiness for each module.
///
/// The graph is resolved first: a missing mandatory field, an unresolved or
/// ambiguous required provider, a role conflict, a self-edge or a required
/// cycle fails the whole set through the typed error path with the exact
/// consumer, capability and (for a cycle) the offending module path. When the
/// graph resolves, every module receives a readiness projection; a module with
/// an unresolved required capability is reported incomplete rather than
/// silently promoted.
pub fn evaluate_module_set_readiness(
    contracts: &[ModuleContract],
    external_providers: &BTreeMap<String, String>,
) -> KernelResult<Vec<GenerationReadinessProjection>> {
    let graph = resolve_required_capability_graph(contracts, external_providers)?;
    Ok(contracts
        .iter()
        .map(|contract| evaluate_generation_readiness(contract, &graph))
        .collect())
}
