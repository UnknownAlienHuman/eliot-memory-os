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

    let mut module_ids: BTreeSet<ContractId> = BTreeSet::new();
    let mut providers: BTreeMap<String, BTreeSet<ContractId>> = BTreeMap::new();
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

    let mut sorted_contracts: Vec<&ModuleContract> = contracts.iter().collect();
    sorted_contracts.sort_by(|left, right| left.module_id.cmp(&right.module_id));

    let mut edges: Vec<RequiredCapabilityEdge> = Vec::new();
    let mut external_bindings: Vec<ExternalCapabilityBinding> = Vec::new();
    let mut degraded: Vec<UnresolvedCapability> = Vec::new();
    for contract in sorted_contracts {
        for capability in &contract.required_capabilities {
            let module_providers = providers.get(capability).cloned().unwrap_or_default();
            let candidates: BTreeSet<&ContractId> = module_providers
                .iter()
                .filter(|provider| **provider != contract.module_id)
                .collect();
            if candidates.is_empty() {
                if module_providers.contains(&contract.module_id) {
                    return Err(RuntimeContractError::SelfCapabilityDependency {
                        module: contract.module_id.to_string(),
                        capability: capability.clone(),
                    });
                }
                if let Some(owner) = external_providers.get(capability) {
                    external_bindings.push(ExternalCapabilityBinding {
                        consumer: contract.module_id.clone(),
                        capability: capability.clone(),
                        owner: owner.clone(),
                    });
                } else {
                    return Err(RuntimeContractError::UnresolvedRequiredCapability {
                        consumer: contract.module_id.to_string(),
                        capability: capability.clone(),
                    });
                }
            } else if candidates.len() > 1 {
                let provider_list = candidates
                    .iter()
                    .map(|provider| provider.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(RuntimeContractError::AmbiguousRequiredCapability {
                    consumer: contract.module_id.to_string(),
                    capability: capability.clone(),
                    providers: provider_list,
                });
            } else {
                let provider = candidates.next().expect("exactly one candidate").clone();
                edges.push(RequiredCapabilityEdge {
                    consumer: contract.module_id.clone(),
                    capability: capability.clone(),
                    provider,
                });
            }
        }
        for (capabilities, role) in [
            (&contract.optional_capabilities, CapabilityRole::Optional),
            (&contract.advisory_capabilities, CapabilityRole::Advisory),
        ] {
            for capability in capabilities {
                if !providers.contains_key(capability)
                    && !external_providers.contains_key(capability)
                {
                    degraded.push(UnresolvedCapability {
                        consumer: contract.module_id.clone(),
                        capability: capability.clone(),
                        kind: role,
                    });
                }
            }
        }
    }

    edges.sort_by(|left, right| {
        left.consumer
            .cmp(&right.consumer)
            .then_with(|| left.capability.cmp(&right.capability))
    });
    external_bindings.sort_by(|left, right| {
        left.consumer
            .cmp(&right.consumer)
            .then_with(|| left.capability.cmp(&right.capability))
    });
    degraded.sort_by(|left, right| {
        left.consumer
            .cmp(&right.consumer)
            .then_with(|| left.capability.cmp(&right.capability))
    });

    let adjacency: BTreeMap<ContractId, BTreeSet<ContractId>> = {
        let mut map: BTreeMap<ContractId, BTreeSet<ContractId>> = BTreeMap::new();
        for edge in &edges {
            map.entry(edge.consumer.clone())
                .or_default()
                .insert(edge.provider.clone());
        }
        map
    };
    if let Some(path) = find_required_capability_cycle(&module_ids, &adjacency) {
        return Err(RuntimeContractError::RequiredCapabilityCycle {
            path: path
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(" -> "),
        });
    }

    let (startup_order, drain_order) = topological_orders(&module_ids, &edges);

    Ok(RequiredCapabilityGraph {
        edges,
        external_bindings,
        startup_order,
        drain_order,
        degraded,
    })
}

/// Depth-first cycle detection returning the actual offending module path.
fn find_required_capability_cycle(
    module_ids: &BTreeSet<ContractId>,
    adjacency: &BTreeMap<ContractId, BTreeSet<ContractId>>,
) -> Option<Vec<ContractId>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Color {
        White,
        Gray,
        Black,
    }

    let mut color: BTreeMap<ContractId, Color> = module_ids
        .iter()
        .map(|id| (id.clone(), Color::White))
        .collect();
    let mut stack: Vec<ContractId> = Vec::new();

    fn visit(
        node: &ContractId,
        adjacency: &BTreeMap<ContractId, BTreeSet<ContractId>>,
        color: &mut BTreeMap<ContractId, Color>,
        stack: &mut Vec<ContractId>,
    ) -> Option<Vec<ContractId>> {
        color.insert(node.clone(), Color::Gray);
        stack.push(node.clone());
        if let Some(providers) = adjacency.get(node) {
            for provider in providers {
                match color.get(provider).copied() {
                    Some(Color::Gray) => {
                        let start = stack
                            .iter()
                            .position(|id| id == provider)
                            .expect("gray node is on the stack");
                        return Some(stack[start..].to_vec());
                    }
                    Some(Color::White) => {
                        if let Some(cycle) = visit(provider, adjacency, color, stack) {
                            return Some(cycle);
                        }
                    }
                    _ => {}
                }
            }
        }
        stack.pop();
        color.insert(node.clone(), Color::Black);
        None
    }

    for node in module_ids {
        if matches!(color.get(node), Some(Color::White)) {
            if let Some(cycle) = visit(node, adjacency, &mut color, &mut stack) {
                return Some(cycle);
            }
        }
    }
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
        .filter(|(_, &degree)| degree == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut startup_order: Vec<ContractId> = Vec::new();
    while let Some(next) = ready.iter().next().cloned() {
        ready.remove(&next);
        startup_order.push(next.clone());
        if let Some(consumers) = reverse.get(&next) {
            for consumer in consumers {
                let degree = in_degree
                    .get_mut(consumer)
                    .expect("consumer present in degree map");
                *degree -= 1;
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
