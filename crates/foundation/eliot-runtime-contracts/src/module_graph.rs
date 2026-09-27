//! Required-capability graph resolution and validation over module contracts.
//!
//! The graph is built only from the `required_capabilities` lists of the
//! admitted [`ModuleContract`] values. Optional and advisory capabilities never
//! become liveness edges: a missing optional/advisory provider is recorded as a
//! degradation, never a deadlock. The resolver validates duplicates,
//! required/optional role conflicts, self-edges and cycles with one
//! deterministic finite pass and returns the actual offending cycle path.
//!
//! This module is a pure legality check over the existing contract dependency
//! lists. It does not own desired-state dependencies (the Governor catalog owns
//! those) and it does not own generation admission (the Kernel owns that).

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::ContractId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ModuleContract, RuntimeContractError};

/// Role of a capability dependency in a module contract.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityRole {
    /// A liveness prerequisite; must resolve to exactly one provider.
    Required,
    /// A capability whose absence degrades but never blocks liveness.
    Optional,
    /// A hint that never affects liveness or readiness.
    Advisory,
}

/// One resolved required-capability edge between two modules.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCapabilityEdge {
    /// Consumer module requiring the capability.
    pub consumer: ContractId,
    /// Capability the consumer requires.
    pub capability: String,
    /// Provider module admitted as the capability owner.
    pub provider: ContractId,
}

/// A required capability bound to an external (non-module) capability owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCapabilityBinding {
    /// Consumer module requiring the capability.
    pub consumer: ContractId,
    /// Capability the consumer requires.
    pub capability: String,
    /// External capability owner identifier.
    pub owner: String,
}

/// A capability with no resolved provider, recorded as a degradation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnresolvedCapability {
    /// Consumer module declaring the capability.
    pub consumer: ContractId,
    /// Capability with no resolved provider.
    pub capability: String,
    /// Role the capability was declared with.
    pub kind: CapabilityRole,
}

/// The resolved required-capability graph over a module set.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCapabilityGraph {
    /// Resolved required edges between modules, in deterministic order.
    pub edges: Vec<RequiredCapabilityEdge>,
    /// Required capabilities bound to an external capability owner.
    pub external_bindings: Vec<ExternalCapabilityBinding>,
    /// Provider-first startup order over the module set.
    pub startup_order: Vec<ContractId>,
    /// Consumer-first drain order over the module set.
    pub drain_order: Vec<ContractId>,
    /// Optional/advisory capabilities with no resolved provider.
    pub degraded: Vec<UnresolvedCapability>,
}

impl RequiredCapabilityGraph {
    /// Returns the resolved required edges for one consumer module.
    pub fn edges_for(&self, module_id: &ContractId) -> Vec<RequiredCapabilityEdge> {
        self.edges
            .iter()
            .filter(|edge| &edge.consumer == module_id)
            .cloned()
            .collect()
    }

    /// Returns the degraded capabilities declared by one consumer module.
    pub fn degraded_for(&self, module_id: &ContractId) -> Vec<UnresolvedCapability> {
        self.degraded
            .iter()
            .filter(|entry| &entry.consumer == module_id)
            .cloned()
            .collect()
    }
}

/// Capability name to the module ids that declare it as provided.
type CapabilityProviders = BTreeMap<String, BTreeSet<ContractId>>;

/// Resolves and validates the required-capability graph over a module set.
///
/// Every contract is validated first, so a missing mandatory field fails closed
/// before any graph reasoning. Each required capability must resolve to exactly
/// one provider module in the set, or to an entry in `external_providers`
/// (the existing external capability owner, such as the Kernel). An unresolved
/// or ambiguous required provider is rejected with the exact consumer and
/// capability. The resolved module edges must be acyclic; a cycle is reported
/// with the actual offending module path. Optional and advisory capabilities
/// never become liveness edges: a missing optional/advisory provider is recorded
/// as a degradation, never a deadlock.
///
/// The startup order is provider-first and the drain order is its exact
/// reverse, both deterministic. A valid graph is necessary but not sufficient
/// for readiness: it manufactures no health, freshness or activation authority.
pub fn resolve_required_capability_graph(
    contracts: &[ModuleContract],
    external_providers: &BTreeMap<String, String>,
) -> Result<RequiredCapabilityGraph, RuntimeContractError> {
    for contract in contracts {
        contract.validate()?;
    }

    let (module_ids, providers) = index_capability_providers(contracts)?;
    let mut resolution = CapabilityResolution::default();
    for contract in sorted_contracts(contracts) {
        resolve_contract_dependencies(contract, &providers, external_providers, &mut resolution)?;
    }
    resolution.sort();

    let adjacency = edge_adjacency(&resolution.edges);
    if let Some(path) = find_required_capability_cycle(&module_ids, &adjacency) {
        return Err(RuntimeContractError::RequiredCapabilityCycle {
            path: path
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" -> "),
        });
    }

    let (startup_order, drain_order) = topological_orders(&module_ids, &resolution.edges);

    Ok(RequiredCapabilityGraph {
        edges: resolution.edges,
        external_bindings: resolution.external_bindings,
        startup_order,
        drain_order,
        degraded: resolution.degraded,
    })
}

/// The deterministic intermediate result of one resolution pass.
#[derive(Default)]
struct CapabilityResolution {
    edges: Vec<RequiredCapabilityEdge>,
    external_bindings: Vec<ExternalCapabilityBinding>,
    degraded: Vec<UnresolvedCapability>,
}

impl CapabilityResolution {
    /// Orders every list by consumer then capability so two runs over equal
    /// input produce equal output.
    fn sort(&mut self) {
        sort_by_consumer_and_capability(
            &mut self.edges,
            |edge| &edge.consumer,
            |edge| edge.capability.as_str(),
        );
        sort_by_consumer_and_capability(
            &mut self.external_bindings,
            |binding| &binding.consumer,
            |binding| binding.capability.as_str(),
        );
        sort_by_consumer_and_capability(
            &mut self.degraded,
            |entry| &entry.consumer,
            |entry| entry.capability.as_str(),
        );
    }
}

/// Orders one resolution list by consumer identity then capability name.
fn sort_by_consumer_and_capability<T>(
    items: &mut [T],
    consumer: impl Fn(&T) -> &ContractId,
    capability: impl Fn(&T) -> &str,
) {
    items.sort_by(|left, right| {
        consumer(left)
            .cmp(consumer(right))
            .then_with(|| capability(left).cmp(capability(right)))
    });
}

/// Indexes the provided capabilities of the admitted module set.
fn index_capability_providers(
    contracts: &[ModuleContract],
) -> Result<(BTreeSet<ContractId>, CapabilityProviders), RuntimeContractError> {
    let mut module_ids: BTreeSet<ContractId> = BTreeSet::new();
    let mut providers: CapabilityProviders = BTreeMap::new();
    for contract in contracts {
        if !module_ids.insert(contract.module_id.clone()) {
            return Err(RuntimeContractError::InvalidField {
                field: "module_id",
                reason: "module contracts must be unique",
            });
        }
        for capability in &contract.capabilities {
            providers
                .entry(capability.clone())
                .or_default()
                .insert(contract.module_id.clone());
        }
    }
    Ok((module_ids, providers))
}

/// Returns the contracts in a deterministic module-id order.
fn sorted_contracts(contracts: &[ModuleContract]) -> Vec<&ModuleContract> {
    let mut sorted: Vec<&ModuleContract> = contracts.iter().collect();
    sorted.sort_by(|left, right| left.module_id.cmp(&right.module_id));
    sorted
}

/// Resolves one contract's required, optional and advisory declarations.
fn resolve_contract_dependencies(
    contract: &ModuleContract,
    providers: &CapabilityProviders,
    external_providers: &BTreeMap<String, String>,
    resolution: &mut CapabilityResolution,
) -> Result<(), RuntimeContractError> {
    for capability in &contract.required_capabilities {
        resolve_required_capability(
            contract,
            capability,
            providers,
            external_providers,
            resolution,
        )?;
    }
    for (capabilities, role) in [
        (&contract.optional_capabilities, CapabilityRole::Optional),
        (&contract.advisory_capabilities, CapabilityRole::Advisory),
    ] {
        collect_degraded_capabilities(
            contract,
            capabilities,
            role,
            providers,
            external_providers,
            resolution,
        );
    }
    Ok(())
}

/// Binds one required capability to its single admitted provider module or to
/// the existing external capability owner.
fn resolve_required_capability(
    contract: &ModuleContract,
    capability: &str,
    providers: &CapabilityProviders,
    external_providers: &BTreeMap<String, String>,
    resolution: &mut CapabilityResolution,
) -> Result<(), RuntimeContractError> {
    let candidates: Vec<ContractId> = providers
        .get(capability)
        .map(|declared| {
            declared
                .iter()
                .filter(|provider| **provider != contract.module_id)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if let Some((provider, additional)) = candidates.split_first() {
        if !additional.is_empty() {
            return Err(RuntimeContractError::AmbiguousRequiredCapability {
                consumer: contract.module_id.to_string(),
                capability: capability.to_owned(),
                providers: candidates
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        resolution.edges.push(RequiredCapabilityEdge {
            consumer: contract.module_id.clone(),
            capability: capability.to_owned(),
            provider: provider.clone(),
        });
        return Ok(());
    }
    if providers
        .get(capability)
        .is_some_and(|declared| declared.contains(&contract.module_id))
    {
        return Err(RuntimeContractError::SelfCapabilityDependency {
            module: contract.module_id.to_string(),
            capability: capability.to_owned(),
        });
    }
    match external_providers.get(capability) {
        Some(owner) => {
            resolution
                .external_bindings
                .push(ExternalCapabilityBinding {
                    consumer: contract.module_id.clone(),
                    capability: capability.to_owned(),
                    owner: owner.clone(),
                });
            Ok(())
        }
        None => Err(RuntimeContractError::UnresolvedRequiredCapability {
            consumer: contract.module_id.to_string(),
            capability: capability.to_owned(),
        }),
    }
}

/// Records optional and advisory capabilities with no resolved provider as
/// visible degradations. They never become liveness edges.
fn collect_degraded_capabilities(
    contract: &ModuleContract,
    capabilities: &[String],
    role: CapabilityRole,
    providers: &CapabilityProviders,
    external_providers: &BTreeMap<String, String>,
    resolution: &mut CapabilityResolution,
) {
    for capability in capabilities {
        if !providers.contains_key(capability) && !external_providers.contains_key(capability) {
            resolution.degraded.push(UnresolvedCapability {
                consumer: contract.module_id.clone(),
                capability: capability.clone(),
                kind: role,
            });
        }
    }
}

/// Builds the consumer-to-provider adjacency used by the cycle pass.
fn edge_adjacency(edges: &[RequiredCapabilityEdge]) -> BTreeMap<ContractId, BTreeSet<ContractId>> {
    let mut adjacency: BTreeMap<ContractId, BTreeSet<ContractId>> = BTreeMap::new();
    for edge in edges {
        adjacency
            .entry(edge.consumer.clone())
            .or_default()
            .insert(edge.provider.clone());
    }
    adjacency
}

/// Depth-first cycle-detection colour of one node.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VisitColor {
    White,
    Gray,
    Black,
}

/// Depth-first cycle detection returning the actual offending module path.
fn find_required_capability_cycle(
    module_ids: &BTreeSet<ContractId>,
    adjacency: &BTreeMap<ContractId, BTreeSet<ContractId>>,
) -> Option<Vec<ContractId>> {
    let mut color: BTreeMap<ContractId, VisitColor> = module_ids
        .iter()
        .map(|id| (id.clone(), VisitColor::White))
        .collect();
    let mut stack: Vec<ContractId> = Vec::new();
    for node in module_ids {
        if !matches!(color.get(node), Some(VisitColor::White)) {
            continue;
        }
        if let Some(cycle) = visit_capability_graph(node, adjacency, &mut color, &mut stack) {
            return Some(cycle);
        }
    }
    None
}

/// Visits one node of the required-capability adjacency, returning the cycle
/// path when a grey provider is reached.
fn visit_capability_graph(
    node: &ContractId,
    adjacency: &BTreeMap<ContractId, BTreeSet<ContractId>>,
    color: &mut BTreeMap<ContractId, VisitColor>,
    stack: &mut Vec<ContractId>,
) -> Option<Vec<ContractId>> {
    color.insert(node.clone(), VisitColor::Gray);
    stack.push(node.clone());
    if let Some(provider_ids) = adjacency.get(node) {
        for provider in provider_ids {
            match color.get(provider).copied() {
                Some(VisitColor::Gray) => {
                    let start = stack.iter().position(|id| id == provider).unwrap_or(0);
                    return Some(stack[start..].to_vec());
                }
                Some(VisitColor::White) => {
                    if let Some(cycle) = visit_capability_graph(provider, adjacency, color, stack) {
                        return Some(cycle);
                    }
                }
                Some(VisitColor::Black) | None => {}
            }
        }
    }
    stack.pop();
    color.insert(node.clone(), VisitColor::Black);
    None
}

/// Computes the provider-first startup order and its exact reverse drain order.
///
/// For every resolved edge `consumer -> provider`, the provider starts first
/// and the consumer drains first. The ready queue is a [`BTreeSet`], so the
/// order is deterministic for a given module set.
fn topological_orders(
    module_ids: &BTreeSet<ContractId>,
    edges: &[RequiredCapabilityEdge],
) -> (Vec<ContractId>, Vec<ContractId>) {
    let mut reverse: BTreeMap<ContractId, BTreeSet<ContractId>> = BTreeMap::new();
    let mut in_degree: BTreeMap<ContractId, usize> =
        module_ids.iter().map(|id| (id.clone(), 0)).collect();
    for edge in edges {
        reverse
            .entry(edge.provider.clone())
            .or_default()
            .insert(edge.consumer.clone());
        *in_degree.entry(edge.consumer.clone()).or_default() += 1;
    }

    let mut ready: BTreeSet<ContractId> = in_degree
        .iter()
        .filter(|&(_, &degree)| degree == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut startup_order: Vec<ContractId> = Vec::new();
    while let Some(next) = ready.iter().next().cloned() {
        ready.remove(&next);
        startup_order.push(next.clone());
        if let Some(consumers) = reverse.get(&next) {
            for consumer in consumers {
                let Some(degree) = in_degree.get_mut(consumer) else {
                    continue;
                };
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    ready.insert(consumer.clone());
                }
            }
        }
    }

    let mut drain_order = startup_order.clone();
    drain_order.reverse();
    (startup_order, drain_order)
}
