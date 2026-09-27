//! Generation-readiness gate over the immutable module contract and its
//! resolved required-capability graph.
//!
//! This module is the Kernel generation/compatibility owner's consumption
//! point for the completed I6.4 contract. It validates the exact contract
//! surface (every mandatory field), retains the admitted manifest and graph
//! identities with the generation record, and reads the module's resolved
//! required edges and degraded capabilities from the graph. It manufactures no
//! health, freshness, test success or activation authority: a valid contract
//! over an acyclic resolved graph is necessary but not sufficient for `READY`,
//! and a `READY` generation is still not `ACTIVE` routing or effect authority.

use std::collections::BTreeMap;

use eliot_contracts::{ContractId, canonical_json_bytes, sha256_hex};
use eliot_runtime_contracts::{
    AdmittedModuleManifest, ModuleContract, RequiredCapabilityEdge, RequiredCapabilityGraph,
    RuntimeContractError, UnresolvedCapability, resolve_required_capability_graph,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{KernelError, KernelResult};

/// Readiness of one module generation before it may reach `READY`.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GenerationReadiness {
    /// The exact contract validates and every required capability is resolved.
    Ready,
    /// A mandatory contract field is missing or a required capability is unresolved.
    Incomplete,
    /// The admitted manifest or graph identity moved since readiness was granted.
    Stale,
}

/// The admitted manifest identities retained with one generation record.
///
/// A generation record keeps the file-byte manifest digest, the canonical
/// parsed-contract digest and the bound artifact identity. A saved `READY` label
/// or a changed source file cannot replace them: the next recheck compares the
/// retained identities against the freshly admitted ones.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationContractIdentity {
    /// Module the identity belongs to.
    pub module_id: ContractId,
    /// File-byte identity of the admitted manifest.
    pub manifest_digest: String,
    /// Canonical parsed-contract identity of the admitted manifest.
    pub contract_digest: String,
    /// Artifact identity the admitted manifest is bound to.
    pub artifact_id: String,
    /// Identity of the resolved required-capability graph the generation read.
    pub graph_digest: String,
}

impl GenerationContractIdentity {
    /// Retains the admitted manifest identities together with the resolved
    /// graph identity a generation was evaluated against.
    pub fn new(
        admitted: &AdmittedModuleManifest,
        graph: &RequiredCapabilityGraph,
    ) -> Result<Self, KernelError> {
        Ok(Self {
            module_id: admitted.module_id.clone(),
            manifest_digest: admitted.manifest_digest.clone(),
            contract_digest: admitted.contract_digest.clone(),
            artifact_id: admitted.artifact_id.to_string(),
            graph_digest: graph_identity(graph)?,
        })
    }
}

/// Returns the canonical identity of one resolved required-capability graph.
///
/// The digest covers the resolved edges, external bindings, startup and drain
/// order and degradations, so a re-resolved graph that moved any binding is a
/// different identity. It is derived from the graph itself and is not a second
/// diagnostic store.
pub fn graph_identity(graph: &RequiredCapabilityGraph) -> Result<String, KernelError> {
    let bytes = canonical_json_bytes(graph).map_err(|error| {
        KernelError::RuntimeContract(RuntimeContractError::MalformedModuleManifest {
            reason: format!(
                "the resolved capability graph is not canonically serialisable: {error}"
            ),
        })
    })?;
    Ok(sha256_hex(&bytes))
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
    /// Admitted manifest and graph identities retained with the generation.
    pub contract_identity: Option<GenerationContractIdentity>,
    /// Blocking reason when the generation is not `Ready`.
    pub blocking_reason: Option<String>,
}

impl GenerationReadinessProjection {
    /// Builds a `Ready` projection that retains the admitted identities.
    pub fn ready(
        contract: &ModuleContract,
        graph: &RequiredCapabilityGraph,
        contract_identity: Option<GenerationContractIdentity>,
    ) -> Self {
        Self {
            module_id: contract.module_id.clone(),
            readiness: GenerationReadiness::Ready,
            resolved_required: graph.edges_for(&contract.module_id),
            degraded_capabilities: graph.degraded_for(&contract.module_id),
            contract_identity,
            blocking_reason: None,
        }
    }

    /// Builds a projection that is not `Ready`, naming the blocking reason.
    pub fn blocked(
        module_id: &ContractId,
        readiness: GenerationReadiness,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            module_id: module_id.clone(),
            readiness,
            resolved_required: Vec::new(),
            degraded_capabilities: Vec::new(),
            contract_identity: None,
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
    evaluate_admitted_generation_readiness(contract, graph, None)
}

/// Evaluates readiness and retains the admitted manifest identities.
///
/// When the admitted manifest is supplied, its file-byte digest, canonical
/// contract digest and bound artifact identity are retained on the projection
/// so a later recheck can detect a substituted manifest.
pub fn evaluate_admitted_generation_readiness(
    contract: &ModuleContract,
    graph: &RequiredCapabilityGraph,
    admitted: Option<&AdmittedModuleManifest>,
) -> GenerationReadinessProjection {
    if let Err(error) = contract.validate() {
        return GenerationReadinessProjection::blocked(
            &contract.module_id,
            GenerationReadiness::Incomplete,
            format!("module contract rejected: {error}"),
        );
    }
    if let Some(admitted) = admitted
        && admitted.contract != *contract
    {
        return GenerationReadinessProjection::blocked(
            &contract.module_id,
            GenerationReadiness::Incomplete,
            format!(
                "admitted manifest {} does not carry the evaluated contract",
                admitted.manifest_digest
            ),
        );
    }

    let missing: Vec<String> = contract
        .required_capabilities
        .iter()
        .filter(|capability| {
            !graph
                .edges_for(&contract.module_id)
                .iter()
                .any(|edge| edge.capability == **capability)
        })
        .cloned()
        .collect();
    if !missing.is_empty() {
        return GenerationReadinessProjection::blocked(
            &contract.module_id,
            GenerationReadiness::Incomplete,
            format!("required capabilities unresolved: {}", missing.join(", ")),
        );
    }

    let identity =
        admitted.and_then(|admitted| GenerationContractIdentity::new(admitted, graph).ok());
    GenerationReadinessProjection::ready(contract, graph, identity)
}

/// Rechecks one consumer generation after a provider replacement, a protocol or
/// configuration change, a revocation or an invalidation.
///
/// The consumer is re-evaluated against the freshly resolved graph. A generation
/// that was previously `Ready` is marked [`GenerationReadiness::Stale`] when the
/// admitted manifest identities or the resolved graph identity moved, so a
/// replaced provider, a substituted manifest or a saved `READY` label cannot
/// retain current readiness. The recheck reports readiness only; it grants no
/// routing or effect authority.
pub fn recheck_after_provider_change(
    contract: &ModuleContract,
    graph: &RequiredCapabilityGraph,
    admitted: Option<&AdmittedModuleManifest>,
    previous: &GenerationReadinessProjection,
) -> GenerationReadinessProjection {
    let current = evaluate_admitted_generation_readiness(contract, graph, admitted);
    if previous.readiness != GenerationReadiness::Ready {
        return current;
    }
    let retained = match (&previous.contract_identity, &current.contract_identity) {
        (Some(retained), Some(current)) => retained == current,
        (None, None) => true,
        _ => false,
    };
    if retained {
        return current;
    }
    GenerationReadinessProjection::blocked(
        &contract.module_id,
        GenerationReadiness::Stale,
        "the admitted manifest or resolved required-capability graph moved since readiness was granted",
    )
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
