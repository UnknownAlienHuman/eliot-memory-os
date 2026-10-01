//! Deterministic A-02 coordination core.
//!
//! The crate plans and reconciles bounded agent attempts. It does not own the
//! task graph, admit authority, mint leases, launch processes, apply effects,
//! or decide task truth. All executable identities arrive in provider-issued
//! receipts and model output remains candidate-only.

#![forbid(unsafe_code)]

mod admitted_provider;
mod core;
mod fair_pull_loop;
mod model;
mod model_control;
mod model_registry;
mod provider_account_catalogue;
mod provider_admission;
mod runtime_profile;
mod swarm_admission_bind;
mod swarm_command_candidate;
mod swarm_controlboard;
mod swarm_definition_admission;
mod swarm_execution_ownership;
mod swarm_launch_bind;
mod swarm_staffing;
#[cfg(test)]
mod tests;

pub use crate::admitted_provider::{AdmittedProviderFactory, OwnerLoadedClaimRow};
pub use crate::core::AgentCoordinator;
pub use crate::fair_pull_loop::{
    FAIR_PULL_LOOP_PROOF_CEILING, FairPullOutcome, FairPullStaleDisposition, FairPullStaleRefusal,
    FairPullStart,
};
pub use crate::model::*;
pub use crate::model_control::*;
pub use crate::model_registry::{
    COMPILED_ROUTE_CANDIDATES_VERSION, CheckDisposition, CompiledRouteCandidates, CostCeiling,
    CoverageState, EvidenceState, HardCheck, MODEL_REGISTRY_SCHEMA_VERSION,
    MODEL_SEARCH_SCHEMA_VERSION, ModelRegistryError, ModelRegistrySnapshot, ModelSearchResult,
    RankingDimension, RankingDisposition, RankingPolicy, RankingPolicyInput, RegistryEvidence,
    RegistryRoute, RejectedRouteResolution, RouteExplanation, RouteRequirements,
    RouteResolutionInput, RouteResolutionRejection, compile_route_candidates, find_models,
    find_models_with_provider_accounts,
};
pub use crate::provider_account_catalogue::{
    AuthDisposition, AuthObservation, ConcurrencyDisposition, ConcurrencyObservation,
    IncidentDisposition, IncidentObservation, PROVIDER_ACCOUNT_CATALOGUE_SCHEMA_VERSION,
    ProviderAccountCatalogueError, ProviderAccountCatalogueSnapshot, ProviderAccountCommand,
    ProviderAccountReadiness, ProviderAccountRow, RateLimitDisposition, RateLimitObservation,
    ReplayDisposition, build_snapshot,
};
pub use crate::provider_admission::{
    AdmittedProviderCapability, OwnerCurrentness, PresentedClaimMaterial, ProviderSelectionHealth,
};
pub use crate::runtime_profile::*;
pub use crate::swarm_admission_bind::*;
pub use crate::swarm_command_candidate::*;
pub use crate::swarm_controlboard::*;
pub use crate::swarm_definition_admission::*;
pub use crate::swarm_execution_ownership::*;
pub use crate::swarm_launch_bind::*;
pub use crate::swarm_staffing::*;

/// Snapshot wire revision. A different revision must be migrated by an
/// external owner before replay.
pub const SNAPSHOT_SCHEMA_VERSION: &str = "eliot-agent-coordinator/snapshot-v4";
