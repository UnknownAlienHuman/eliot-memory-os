//! Provider-first startup and reverse-required drain ordering over the resolved
//! required-capability graph.
//!
//! `I6.4` fixes the lifecycle order: startup follows required dependencies and
//! drain runs in reverse. This module turns the resolved graph into that order
//! and answers the two mechanical questions a coordinator asks:
//!
//! * which modules may start *now*, given the provider readiness and freshness
//!   that were actually observed; and
//! * which modules may drain now, given the consumers that have already
//!   quiesced.
//!
//! Acyclic topology alone is not sufficient. A module becomes startable only
//! when every module it actually requires is observed `Ready` and fresh, and
//! optional/advisory capabilities never appear in either question because they
//! are not liveness edges: a missing optional provider degrades the dependent
//! capability and never becomes a recursive startup wait. The order carries no
//! authority of its own — it is a proposal the existing coordinator executes.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::ContractId;
use eliot_runtime_contracts::{RequiredCapabilityEdge, RequiredCapabilityGraph};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::module::generation_readiness::GenerationReadiness;

/// One module's place in one phase of the provider-first lifecycle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStep {
    /// Module the step applies to.
    pub module_id: ContractId,
    /// Resolved required edges this step waits on. Empty for a provider that
    /// requires nothing inside the admitted module set.
    pub requires: Vec<RequiredCapabilityEdge>,
}

/// The provider-first startup order and its exact reverse drain order.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleOrder {
    /// Provider-first startup steps.
    pub startup: Vec<LifecycleStep>,
    /// Consumer-first drain steps, the exact reverse of `startup`.
    pub drain: Vec<LifecycleStep>,
}

/// What an owner has actually observed about one provider module.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderObservation {
    /// Readiness the owner observed for the provider.
    pub readiness: GenerationReadiness,
    /// Whether the provider's derived state was observed fresh. A provider that
    /// has not been observed fresh is not startable for its consumers.
    pub fresh: bool,
}

/// Derives the provider-first startup order and reverse drain order from the
/// resolved required-capability graph.
///
/// The graph already validated that the required topology is acyclic, so the
/// order is a finite linearisation rather than a sort of arbitrary input.
pub fn provider_first_lifecycle_order(graph: &RequiredCapabilityGraph) -> LifecycleOrder {
    let startup: Vec<LifecycleStep> = graph
        .startup_order
        .iter()
        .map(|module_id| LifecycleStep {
            module_id: module_id.clone(),
            requires: graph.edges_for(module_id),
        })
        .collect();
    let drain: Vec<LifecycleStep> = startup.iter().rev().cloned().collect();
    LifecycleOrder { startup, drain }
}

/// Returns the modules whose required providers are all observed ready and
/// fresh, in provider-first order.
///
/// A module with an unobserved, not-ready or stale provider is not returned, so
/// a cyclic-looking startup wait cannot form: the answer only ever grows as
/// providers are observed. Optional and advisory capabilities are not consulted.
pub fn startup_ready_now(
    order: &LifecycleOrder,
    observed: &BTreeMap<ContractId, ProviderObservation>,
) -> Vec<ContractId> {
    order
        .startup
        .iter()
        .filter(|step| providers_are_satisfied(step, observed))
        .map(|step| step.module_id.clone())
        .collect()
}

/// Returns the modules whose consumers have all quiesced, in consumer-first
/// order.
///
/// A provider stays in the order until every consumer that actually requires it
/// has quiesced, so a data or receipt dependency is not torn down before its
/// existing drain obligations finish.
pub fn drain_ready_now(order: &LifecycleOrder, quiesced: &BTreeSet<ContractId>) -> Vec<ContractId> {
    let mut remaining: BTreeMap<ContractId, BTreeSet<ContractId>> = BTreeMap::new();
    for step in &order.startup {
        for edge in &step.requires {
            remaining
                .entry(edge.provider.clone())
                .or_default()
                .insert(step.module_id.clone());
        }
    }
    let ready: BTreeSet<ContractId> = quiesced.clone();
    order
        .drain
        .iter()
        .filter(|step| {
            remaining
                .get(&step.module_id)
                .is_none_or(|consumers| consumers.iter().all(|consumer| ready.contains(consumer)))
        })
        .map(|step| step.module_id.clone())
        .collect()
}

/// Returns whether every module this step actually requires is observed ready
/// and fresh.
fn providers_are_satisfied(
    step: &LifecycleStep,
    observed: &BTreeMap<ContractId, ProviderObservation>,
) -> bool {
    step.requires.iter().all(|edge| {
        observed.get(&edge.provider).is_some_and(|observation| {
            observation.readiness == GenerationReadiness::Ready && observation.fresh
        })
    })
}
