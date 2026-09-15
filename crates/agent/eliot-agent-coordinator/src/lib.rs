//! Deterministic A-02 coordination core.
//!
//! The crate plans and reconciles bounded agent attempts. It does not own the
//! task graph, admit authority, mint leases, launch processes, apply effects,
//! or decide task truth. All executable identities arrive in provider-issued
//! receipts and model output remains candidate-only.

#![forbid(unsafe_code)]

mod core;
mod model;
mod model_control;
mod model_registry;
mod provider_account_catalogue;
mod provider_admission;
mod swarm_command_candidate;
mod swarm_controlboard;
mod swarm_staffing;
#[cfg(test)]
mod tests;

pub use crate::core::AgentCoordinator;
pub use crate::model::*;
pub use crate::model_control::*;
pub use crate::model_registry::{
    CheckDisposition, CostCeiling, CoverageState, EvidenceState, HardCheck,
    MODEL_REGISTRY_SCHEMA_VERSION, MODEL_SEARCH_SCHEMA_VERSION, ModelRegistryError,
    ModelRegistrySnapshot, ModelSearchResult, RankingDimension, RankingDisposition, RankingPolicy,
    RankingPolicyInput, RegistryEvidence, RegistryRoute, RouteExplanation, RouteRequirements,
    find_models, find_models_with_provider_accounts,
};
pub use crate::provider_account_catalogue::{
    AuthDisposition, AuthObservation, ConcurrencyDisposition, ConcurrencyObservation,
    IncidentDisposition, IncidentObservation, PROVIDER_ACCOUNT_CATALOGUE_SCHEMA_VERSION,
    ProviderAccountCatalogueError, ProviderAccountCatalogueSnapshot, ProviderAccountCommand,
    ProviderAccountReadiness, ProviderAccountRow, RateLimitDisposition, RateLimitObservation,
    ReplayDisposition, build_snapshot,
};
pub use crate::provider_admission::AdmittedProviderCapability;
pub use crate::swarm_command_candidate::*;
pub use crate::swarm_controlboard::*;
pub use crate::swarm_staffing::*;

/// Snapshot wire revision. A different revision must be migrated by an
/// external owner before replay.
pub const SNAPSHOT_SCHEMA_VERSION: &str = "eliot-agent-coordinator/snapshot-v4";
