//! Governor-owned Module Catalog contracts.
//!
//! The catalog owns desired semantic configuration and admission intent. It
//! does not own PIDs, pipes, Job Objects, process health, route cutover, or
//! Kernel operational recovery state. A generation admission is an immutable
//! handoff to the Kernel Generation Registry; it is not activation authority.
//!
//! It also owns the declared invalidation graph
//! ([`ModuleDependency::invalidation_triggers`]) and the versioned restart policy
//! ([`ModuleManifest::restart_policy`]). [`ModuleCatalog::select_invalidation_dependents`]
//! answers "which modules does replacing this one actually invalidate?" from
//! those declared edges, and the answer is recorded on
//! [`PreparedCatalogTransition::invalidated_dependents`] so the owner that
//! performs the restart cannot substitute a different set. Selecting by startup
//! order, by iteration order, or by "everything currently running" is the defect
//! this module exists to prevent.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{
    ContractVersion, OperationId, RequestMetadata, ResourceGeneration, StateFence,
    canonical_json_bytes, sha256_hex,
};
use eliot_runtime_contracts::{
    RestartDependencyKind, RestartGroupStrategy, RestartInvalidationTrigger,
    RestartPolicyDisposition, RestartPolicyV1, dispose_restart_policy,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.governor.module-registry";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

fn text(value: &str, field: &'static str) -> Result<(), ModuleError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ModuleError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ModuleError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ModuleError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, ModuleError> {
    canonical_json_bytes(value).map_err(|error| ModuleError::Serialization(error.to_string()))
}

fn digest_value<T: Serialize>(value: &T) -> Result<String, ModuleError> {
    Ok(sha256_hex(&canonical(value)?))
}

fn unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), ModuleError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(ModuleError::Duplicate { field });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("invalid module registry field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("duplicate module registry value in {field}")]
    Duplicate { field: &'static str },
    #[error("module registry state fence mismatch")]
    FenceMismatch,
    #[error("module catalog revision conflict")]
    RevisionConflict,
    #[error("module catalog entry not found")]
    NotFound,
    #[error("module generation admission receipt has not been read back from its owner")]
    AdmissionReceiptUnverified,
    #[error("module catalog operation identity conflict")]
    IdentityConflict,
    /// The declared required dependency edges contain a cycle.
    #[error("module catalog required dependency cycle: {path}")]
    RequiredDependencyCycle { path: String },
    #[error("module catalog serialization failed: {0}")]
    Serialization(String),
    #[error("module catalog contract failed: {0}")]
    Contract(String),
}

/// Stable identity for a Governor-owned desired module.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModuleId(String);

impl ModuleId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModuleError> {
        let value = value.into();
        text(&value, "module_id")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ModuleId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

macro_rules! id_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModuleError> {
                let value = value.into();
                text(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

id_type!(GenerationId, "generation_id");
id_type!(CatalogReceiptId, "catalog_receipt_id");
id_type!(CapabilityId, "capability_id");

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredModuleState {
    Enabled,
    Disabled,
    Quarantined,
    Removed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectCeiling {
    ReadRebuild,
    CandidateOnly,
    EffectExactLease,
}

impl EffectCeiling {
    fn rank(self) -> u8 {
        match self {
            Self::ReadRebuild => 0,
            Self::CandidateOnly => 1,
            Self::EffectExactLease => 2,
        }
    }

    #[must_use]
    pub fn admits(self, requested: Self) -> bool {
        requested.rank() <= self.rank()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartAuthorization {
    ReadRebuild,
    EffectExactLease,
    CurrentCatalogRequired,
}

/// One declared edge of a module's invalidation graph.
///
/// An edge names the depended-upon module, the protocol digest this module
/// requires of it, the startup order, and — the part that makes it an
/// *invalidation* edge rather than only an ordering hint — the exact triggers
/// that invalidate **this** module when the depended-upon module is restarted or
/// replaced.
///
/// `startup_order` alone never qualifies an edge: it records when a module may
/// start, not what invalidates it. A dependent is selected for recovery only
/// because it declared a trigger here, so a later-started unrelated child is
/// never swept into a restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleDependency {
    pub module_id: ModuleId,
    pub required_protocol_digest: String,
    pub startup_order: u32,
    /// How this dependency affects activation and recovery. An optional or
    /// advisory edge whose provider is absent degrades this module's capability
    /// and never becomes a liveness edge.
    pub kind: RestartDependencyKind,
    /// Triggers on the depended-upon module that invalidate this module. An
    /// empty list declares "this dependency never invalidates me", which is a
    /// real declaration and not an absent one.
    pub invalidation_triggers: Vec<RestartInvalidationTrigger>,
}

impl ModuleDependency {
    pub fn validate(&self) -> Result<(), ModuleError> {
        digest(
            &self.required_protocol_digest,
            "dependency.required_protocol_digest",
        )?;
        unique(
            self.invalidation_triggers.iter().copied(),
            "dependency.invalidation_triggers",
        )?;
        Ok(())
    }

    /// Whether this edge declares that `trigger` on the depended-upon module
    /// invalidates this module.
    #[must_use]
    pub fn invalidated_by(&self, trigger: RestartInvalidationTrigger) -> bool {
        self.invalidation_triggers.contains(&trigger)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityIntent {
    pub capability_id: CapabilityId,
    pub effect_ceiling: EffectCeiling,
    pub allowed_scopes: Vec<String>,
    pub privacy_classes: Vec<String>,
}

impl CapabilityIntent {
    pub fn validate(&self) -> Result<(), ModuleError> {
        unique(
            self.allowed_scopes.iter().cloned(),
            "capability.allowed_scopes",
        )?;
        unique(
            self.privacy_classes.iter().cloned(),
            "capability.privacy_classes",
        )?;
        for scope in self.allowed_scopes.iter().chain(&self.privacy_classes) {
            text(scope, "capability.scope_or_privacy")?;
        }
        Ok(())
    }
}

/// Governor-owned route scope for one admitted module capability.
///
/// The coordinates are source policy. The stable hash binds those coordinates
/// for the Kernel projection; it is never used to reconstruct them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCapabilityRouteScope {
    pub module_id: ModuleId,
    pub capability_id: CapabilityId,
    pub work_scope: String,
    pub effect_domain: String,
    pub route_scope_hash: String,
}

impl ModuleCapabilityRouteScope {
    /// Declares an exact route scope and binds its stable hash.
    pub fn declare(
        module_id: ModuleId,
        capability_id: CapabilityId,
        work_scope: impl Into<String>,
        effect_domain: impl Into<String>,
    ) -> Result<Self, ModuleError> {
        let mut value = Self {
            module_id,
            capability_id,
            work_scope: work_scope.into(),
            effect_domain: effect_domain.into(),
            route_scope_hash: String::new(),
        };
        value.route_scope_hash = value.computed_hash()?;
        value.validate()?;
        Ok(value)
    }

    fn computed_hash(&self) -> Result<String, ModuleError> {
        text(self.module_id.as_str(), "route_scope.module_id")?;
        text(self.capability_id.as_str(), "route_scope.capability_id")?;
        text(&self.work_scope, "route_scope.work_scope")?;
        text(&self.effect_domain, "route_scope.effect_domain")?;
        let identity = format!(
            "{}\0{}\0{}\0{}",
            self.module_id, self.capability_id, self.work_scope, self.effect_domain
        );
        Ok(sha256_hex(identity.as_bytes()))
    }

    pub fn validate(&self) -> Result<(), ModuleError> {
        digest(&self.route_scope_hash, "route_scope.route_scope_hash")?;
        if self.computed_hash()? != self.route_scope_hash {
            return Err(ModuleError::IdentityConflict);
        }
        Ok(())
    }
}

/// Windows Job Object policy values owned by the admitted Module Manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleResourceLimits {
    pub job_object_policy: String,
    pub max_processes: u32,
    pub max_working_set_bytes: u64,
    pub cpu_rate_control_percent: u16,
}

impl ModuleResourceLimits {
    fn validate(&self) -> Result<(), ModuleError> {
        text(&self.job_object_policy, "resource_limits.job_object_policy")?;
        if self.max_processes == 0 {
            return Err(ModuleError::InvalidField {
                field: "resource_limits.max_processes",
                reason: "must be greater than zero",
            });
        }
        if self.max_working_set_bytes == 0 {
            return Err(ModuleError::InvalidField {
                field: "resource_limits.max_working_set_bytes",
                reason: "must be greater than zero",
            });
        }
        if !(1..=100).contains(&self.cpu_rate_control_percent) {
            return Err(ModuleError::InvalidField {
                field: "resource_limits.cpu_rate_control_percent",
                reason: "must be between 1 and 100",
            });
        }
        Ok(())
    }
}

/// Bounded module restart budget and its quarantine disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleRestartBudget {
    pub max_restarts: u32,
    pub quarantine_rule: String,
}

impl ModuleRestartBudget {
    fn validate(&self) -> Result<(), ModuleError> {
        if self.max_restarts == 0 {
            return Err(ModuleError::InvalidField {
                field: "restart_budget.max_restarts",
                reason: "must be greater than zero",
            });
        }
        text(&self.quarantine_rule, "restart_budget.quarantine_rule")
    }
}

/// State-class behavior declared for a generation cutover.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleStateClassBehavior {
    RetainCompatible,
    CheckpointTransfer,
    RebuildFromSnapshot,
    ForwardRepairRequired,
}

/// Explicit source-owned execution values copied into a Kernel projection.
///
/// This policy is stored with the desired Module Manifest. Preparation reads
/// the exact admitted row and supplies no defaults. It grants no activation
/// authority; Kernel still owns generation admission and route cutover.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationExecutionPolicy {
    pub policy_revision: u64,
    pub allowed_route_scopes: Vec<ModuleCapabilityRouteScope>,
    pub resource_limits: ModuleResourceLimits,
    pub restart_budget: ModuleRestartBudget,
    pub state_class_behavior: ModuleStateClassBehavior,
}

impl GenerationExecutionPolicy {
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.policy_revision == 0 {
            return Err(ModuleError::InvalidField {
                field: "execution_policy.policy_revision",
                reason: "must be greater than zero",
            });
        }
        self.resource_limits.validate()?;
        self.restart_budget.validate()?;
        unique(
            self.allowed_route_scopes
                .iter()
                .map(|scope| scope.route_scope_hash.clone()),
            "execution_policy.allowed_route_scopes",
        )?;
        for scope in &self.allowed_route_scopes {
            scope.validate()?;
        }
        Ok(())
    }

    fn validate_for_module(
        &self,
        module_id: &ModuleId,
        manifest: &ModuleManifest,
    ) -> Result<(), ModuleError> {
        self.validate()?;
        for scope in &self.allowed_route_scopes {
            if &scope.module_id != module_id {
                return Err(ModuleError::IdentityConflict);
            }
            let intent = manifest
                .capability_intents
                .iter()
                .find(|intent| intent.capability_id == scope.capability_id)
                .ok_or(ModuleError::IdentityConflict)?;
            if !intent
                .allowed_scopes
                .iter()
                .any(|allowed| allowed == &scope.work_scope)
                || !manifest.effect_ceiling.admits(intent.effect_ceiling)
            {
                return Err(ModuleError::IdentityConflict);
            }
        }
        if manifest.effect_ceiling == EffectCeiling::EffectExactLease
            && self.allowed_route_scopes.is_empty()
        {
            return Err(ModuleError::InvalidField {
                field: "execution_policy.allowed_route_scopes",
                reason: "effect-capable generations require an admitted route scope",
            });
        }
        Ok(())
    }
}

/// Desired execution description. It carries references and hashes, never
/// secret values, process handles, or a mutable route.
///
/// `restart_policy` is the one versioned restart contract the catalog owns
/// (I14.10 / I8.12). It sits beside `effect_ceiling` and
/// `restart_authorization` rather than replacing either: the policy bounds
/// *whether* a child restarts and how often, while those two keep constraining
/// *what* an admitted child may do. `None` is not a permissive default — a
/// manifest that declares no versioned policy is recorded as an explicit
/// withheld disposition on [`ModuleCatalogEntry`], which permits no automatic
/// restart at all.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleManifest {
    pub artifact_digest: String,
    pub config_digest: String,
    pub protocol_digest: String,
    pub command_ref: String,
    pub health_contract_ref: String,
    pub dependencies: Vec<ModuleDependency>,
    pub capability_intents: Vec<CapabilityIntent>,
    pub effect_ceiling: EffectCeiling,
    pub restart_authorization: RestartAuthorization,
    pub restart_policy: Option<RestartPolicyV1>,
    pub approved_scope_refs: Vec<String>,
    /// Source-owned values required to prepare a Kernel execution projection.
    /// Absence remains explicit and never selects runtime defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_policy: Option<GenerationExecutionPolicy>,
    pub manifest_digest: String,
}

impl ModuleManifest {
    /// Constructs the wire manifest from its canonical public fields.
    ///
    /// The explicit arity mirrors the serialized/API contract; grouping these
    /// values would be a public constructor change.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_digest: String,
        config_digest: String,
        protocol_digest: String,
        command_ref: String,
        health_contract_ref: String,
        dependencies: Vec<ModuleDependency>,
        capability_intents: Vec<CapabilityIntent>,
        effect_ceiling: EffectCeiling,
        restart_authorization: RestartAuthorization,
        restart_policy: Option<RestartPolicyV1>,
        approved_scope_refs: Vec<String>,
    ) -> Result<Self, ModuleError> {
        let mut value = Self {
            artifact_digest,
            config_digest,
            protocol_digest,
            command_ref,
            health_contract_ref,
            dependencies,
            capability_intents,
            effect_ceiling,
            restart_authorization,
            restart_policy,
            approved_scope_refs,
            execution_policy: None,
            manifest_digest: String::new(),
        };
        value.manifest_digest = value.identity_digest()?;
        value.validate()?;
        Ok(value)
    }

    /// Adds explicit source-owned execution values and rebinds the manifest
    /// digest to the complete declaration.
    pub fn with_execution_policy(
        mut self,
        execution_policy: GenerationExecutionPolicy,
    ) -> Result<Self, ModuleError> {
        execution_policy.validate()?;
        self.execution_policy = Some(execution_policy);
        self.manifest_digest = self.identity_digest()?;
        self.validate()?;
        Ok(self)
    }

    /// Returns the digest of the exact declared capability profile.
    ///
    /// Artifact, config and protocol identities are carried separately by a
    /// generation candidate. This projection binds the module identity,
    /// capability intents, overall effect ceiling, approved scopes, and the
    /// execution policy that narrows those intents for Kernel. It is semantic
    /// catalog content, not build-source provenance.
    pub fn capability_profile_digest(&self, module_id: &ModuleId) -> Result<String, ModuleError> {
        #[derive(Serialize)]
        struct CapabilityProfile<'a> {
            domain: &'static str,
            module_id: &'a ModuleId,
            effect_ceiling: EffectCeiling,
            capability_intents: &'a [CapabilityIntent],
            approved_scope_refs: &'a [String],
            execution_policy: &'a Option<GenerationExecutionPolicy>,
        }

        digest_value(&CapabilityProfile {
            domain: "eliot.module-capability-profile.v1",
            module_id,
            effect_ceiling: self.effect_ceiling,
            capability_intents: &self.capability_intents,
            approved_scope_refs: &self.approved_scope_refs,
            execution_policy: &self.execution_policy,
        })
    }

    fn identity_digest(&self) -> Result<String, ModuleError> {
        #[derive(Serialize)]
        struct Identity<'a> {
            artifact_digest: &'a str,
            config_digest: &'a str,
            protocol_digest: &'a str,
            command_ref: &'a str,
            health_contract_ref: &'a str,
            dependencies: &'a [ModuleDependency],
            capability_intents: &'a [CapabilityIntent],
            effect_ceiling: EffectCeiling,
            restart_authorization: RestartAuthorization,
            restart_policy: &'a Option<RestartPolicyV1>,
            approved_scope_refs: &'a [String],
            #[serde(skip_serializing_if = "Option::is_none")]
            execution_policy: &'a Option<GenerationExecutionPolicy>,
        }

        digest_value(&Identity {
            artifact_digest: &self.artifact_digest,
            config_digest: &self.config_digest,
            protocol_digest: &self.protocol_digest,
            command_ref: &self.command_ref,
            health_contract_ref: &self.health_contract_ref,
            dependencies: &self.dependencies,
            capability_intents: &self.capability_intents,
            effect_ceiling: self.effect_ceiling,
            restart_authorization: self.restart_authorization,
            restart_policy: &self.restart_policy,
            approved_scope_refs: &self.approved_scope_refs,
            execution_policy: &self.execution_policy,
        })
    }

    pub fn validate(&self) -> Result<(), ModuleError> {
        digest(&self.artifact_digest, "artifact_digest")?;
        digest(&self.config_digest, "config_digest")?;
        digest(&self.protocol_digest, "protocol_digest")?;
        text(&self.command_ref, "command_ref")?;
        text(&self.health_contract_ref, "health_contract_ref")?;
        unique(
            self.dependencies
                .iter()
                .map(|dependency| dependency.module_id.clone()),
            "dependencies.module_id",
        )?;
        unique(
            self.dependencies
                .iter()
                .map(|dependency| dependency.startup_order),
            "dependencies.startup_order",
        )?;
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        unique(
            self.capability_intents
                .iter()
                .map(|intent| intent.capability_id.clone()),
            "capability_intents.capability_id",
        )?;
        for intent in &self.capability_intents {
            intent.validate()?;
        }
        // A declared policy is admitted only when the shared contract admits
        // it. An absent or unsupported declaration is carried to the catalog
        // entry and dispositioned there; it never becomes an implicit policy.
        if let Some(policy) = &self.restart_policy {
            policy
                .validate()
                .map_err(|error| ModuleError::Contract(error.to_string()))?;
        }
        unique(
            self.approved_scope_refs.iter().cloned(),
            "approved_scope_refs",
        )?;
        for scope in &self.approved_scope_refs {
            text(scope, "approved_scope_ref")?;
        }
        if let Some(policy) = &self.execution_policy {
            policy.validate()?;
        }
        digest(&self.manifest_digest, "manifest_digest")?;
        if self.identity_digest()? != self.manifest_digest {
            return Err(ModuleError::IdentityConflict);
        }
        Ok(())
    }

    fn validate_for_module(&self, module_id: &ModuleId) -> Result<(), ModuleError> {
        self.validate()?;
        if let Some(policy) = &self.execution_policy {
            policy.validate_for_module(module_id, self)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCandidateReceipt {
    pub candidate_id: GenerationId,
    pub module_id: ModuleId,
    pub artifact_digest: String,
    pub config_digest: String,
    pub protocol_digest: String,
    /// Digest of the independently owner-issued build/source provenance row.
    pub build_provenance_digest: String,
    /// Digest from [`ModuleManifest::capability_profile_digest`] for this module.
    pub capability_profile_digest: String,
    /// Digest of the build/source owner's fence; it is not the Governor
    /// admission `StateFence` unless that owner explicitly defines the same
    /// identity.
    pub source_fence_digest: String,
    pub candidate_digest: String,
}

impl GenerationCandidateReceipt {
    /// Creates a self-digested candidate wire value.
    ///
    /// This constructor proves only internal digest consistency. It does not
    /// establish that a builder/source owner issued the supplied provenance
    /// values; production admission must join them to that owner's current
    /// independent record before accepting this receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_id: GenerationId,
        module_id: ModuleId,
        artifact_digest: String,
        config_digest: String,
        protocol_digest: String,
        build_provenance_digest: String,
        capability_profile_digest: String,
        source_fence_digest: String,
    ) -> Result<Self, ModuleError> {
        let mut value = Self {
            candidate_id,
            module_id,
            artifact_digest,
            config_digest,
            protocol_digest,
            build_provenance_digest,
            capability_profile_digest,
            source_fence_digest,
            candidate_digest: String::new(),
        };
        value.candidate_digest = value.identity_digest()?;
        value.validate()?;
        Ok(value)
    }

    fn identity_digest(&self) -> Result<String, ModuleError> {
        digest_value(&(
            &self.candidate_id,
            &self.module_id,
            &self.artifact_digest,
            &self.config_digest,
            &self.protocol_digest,
            &self.build_provenance_digest,
            &self.capability_profile_digest,
            &self.source_fence_digest,
        ))
    }

    pub fn validate(&self) -> Result<(), ModuleError> {
        digest(&self.artifact_digest, "candidate.artifact_digest")?;
        digest(&self.config_digest, "candidate.config_digest")?;
        digest(&self.protocol_digest, "candidate.protocol_digest")?;
        digest(
            &self.build_provenance_digest,
            "candidate.build_provenance_digest",
        )?;
        digest(
            &self.capability_profile_digest,
            "candidate.capability_profile_digest",
        )?;
        digest(&self.source_fence_digest, "candidate.source_fence_digest")?;
        digest(&self.candidate_digest, "candidate.candidate_digest")?;
        if self.identity_digest()? != self.candidate_digest {
            return Err(ModuleError::IdentityConflict);
        }
        Ok(())
    }
}

/// Immutable execution projection copied from an admitted catalog entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelExecutionManifest {
    pub module_id: ModuleId,
    pub generation_id: GenerationId,
    pub artifact_digest: String,
    pub config_digest: String,
    pub protocol_digest: String,
    pub command_ref: String,
    pub health_contract_ref: String,
    pub effect_ceiling: EffectCeiling,
    pub restart_authorization: RestartAuthorization,
    /// Digest of the versioned restart policy this generation is admitted
    /// under. It travels with the projection so the accepted generation cannot
    /// be supervised under a policy revision other than the one the catalog
    /// admitted.
    pub restart_policy_digest: String,
    pub accepted_catalog_revision: u64,
    pub accepted_catalog_receipt: CatalogReceiptId,
    pub manifest_digest: String,
}

impl KernelExecutionManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        module_id: ModuleId,
        generation_id: GenerationId,
        artifact_digest: String,
        config_digest: String,
        protocol_digest: String,
        command_ref: String,
        health_contract_ref: String,
        effect_ceiling: EffectCeiling,
        restart_authorization: RestartAuthorization,
        restart_policy_digest: String,
        accepted_catalog_revision: u64,
        accepted_catalog_receipt: CatalogReceiptId,
    ) -> Result<Self, ModuleError> {
        let mut value = Self {
            module_id,
            generation_id,
            artifact_digest,
            config_digest,
            protocol_digest,
            command_ref,
            health_contract_ref,
            effect_ceiling,
            restart_authorization,
            restart_policy_digest,
            accepted_catalog_revision,
            accepted_catalog_receipt,
            manifest_digest: String::new(),
        };
        value.manifest_digest = value.identity_digest()?;
        value.validate()?;
        Ok(value)
    }

    fn identity_digest(&self) -> Result<String, ModuleError> {
        digest_value(&(
            &self.module_id,
            &self.generation_id,
            &self.artifact_digest,
            &self.config_digest,
            &self.protocol_digest,
            &self.command_ref,
            &self.health_contract_ref,
            self.effect_ceiling,
            self.restart_authorization,
            &self.restart_policy_digest,
            self.accepted_catalog_revision,
            &self.accepted_catalog_receipt,
        ))
    }

    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.accepted_catalog_revision == 0 {
            return Err(ModuleError::InvalidField {
                field: "accepted_catalog_revision",
                reason: "must be non-zero",
            });
        }
        // I1.9: the accepted Module Catalog revision travels with its
        // lifecycle/admission receipt. A receipt-less projection is not an
        // admission, so it validates as unusable rather than issuable.
        text(
            self.accepted_catalog_receipt.as_str(),
            "execution.accepted_catalog_receipt",
        )?;
        digest(&self.artifact_digest, "execution.artifact_digest")?;
        digest(&self.config_digest, "execution.config_digest")?;
        digest(&self.protocol_digest, "execution.protocol_digest")?;
        text(&self.command_ref, "execution.command_ref")?;
        text(&self.health_contract_ref, "execution.health_contract_ref")?;
        digest(
            &self.restart_policy_digest,
            "execution.restart_policy_digest",
        )?;
        digest(&self.manifest_digest, "execution.manifest_digest")?;
        if self.identity_digest()? != self.manifest_digest {
            return Err(ModuleError::IdentityConflict);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationAdmission {
    pub candidate: GenerationCandidateReceipt,
    pub execution: KernelExecutionManifest,
    pub catalog_revision: u64,
    pub state_fence: StateFence,
    pub admission_receipt: CatalogReceiptId,
}

impl GenerationAdmission {
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.candidate.validate()?;
        self.execution.validate()?;
        // I1.9: the Governor issues the lifecycle/admission receipt with the
        // revision. An admission without one cannot authorize a Kernel
        // manifest, so it is rejected at issuance, not downstream.
        text(self.admission_receipt.as_str(), "admission_receipt")?;
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        // These are structural/manifest joins only. In particular,
        // `source_fence_digest` belongs to the independent build/source owner
        // and is not guessed to be a digest of this admission fence.
        if self.catalog_revision == 0
            || self.catalog_revision != self.execution.accepted_catalog_revision
            || self.candidate.module_id != self.execution.module_id
            || self.candidate.candidate_id != self.execution.generation_id
            || self.candidate.artifact_digest != self.execution.artifact_digest
            || self.candidate.config_digest != self.execution.config_digest
            || self.candidate.protocol_digest != self.execution.protocol_digest
            || self.admission_receipt != self.execution.accepted_catalog_receipt
        {
            return Err(ModuleError::IdentityConflict);
        }
        Ok(())
    }
}

/// Seals one verified [`GenerationAdmission`] into the single canonical sealed
/// projection a Kernel Generation Registry copy is made from:
/// [`eliot_ors::GovernorGenerationAdmissionSeal`].
///
/// This is the only adapter from this owner contract to that projection, so
/// there is exactly one spelling of the field-by-field mapping and one seal
/// version it is recorded under. The projection itself is owned by the Kernel
/// side; nothing here restates or redeclares it.
///
/// The change must be the accepted-generation change itself, the row must be the
/// row that accepted it at the expected revision and State Fence, and the
/// operation identity, module, catalog revision, policy revision, accepted
/// manifest digest, State Fence snapshot and lifecycle disposition are copied
/// from those owner values. A mismatch is refused rather than resolved: a stale
/// revision, a different fence, a row that does not carry this exact admission,
/// a module or generation that differs from the row, a withheld restart policy,
/// or an admitting fence with no policy revision all name the gap instead of
/// producing a seal with a substituted field.
pub fn seal_generation_admission(
    change: &ModuleCatalogChange,
    entry: &ModuleCatalogEntry,
    expected_catalog_revision: u64,
    expected_state_fence: &StateFence,
) -> Result<eliot_ors::GovernorGenerationAdmissionSeal, ModuleError> {
    change.validate()?;
    entry.validate()?;
    let CatalogMutation::AcceptGeneration { admission } = &change.mutation else {
        return Err(ModuleError::InvalidField {
            field: "mutation",
            reason: "a seal is issued only for an accepted-generation change",
        });
    };
    admission.validate()?;
    if entry.module_id != change.module_id {
        return Err(ModuleError::IdentityConflict);
    }
    // The seal is issued for the revision this admission was accepted at. A
    // catalog that has since moved on has no current admission to seal, so a
    // later revision is refused rather than sealed under a revision the
    // admission never named.
    if expected_catalog_revision == 0 || expected_catalog_revision != admission.catalog_revision {
        return Err(ModuleError::RevisionConflict);
    }
    expected_state_fence
        .validate()
        .map_err(|error| ModuleError::Contract(error.to_string()))?;
    if admission.state_fence != *expected_state_fence || entry.state_fence != *expected_state_fence
    {
        return Err(ModuleError::FenceMismatch);
    }
    // The owner row must carry this exact admission, so a replaced or unrelated
    // candidate cannot be sealed under a receipt that names another one.
    if entry.accepted_generation.as_ref() != Some(admission) {
        return Err(ModuleError::AdmissionReceiptUnverified);
    }
    if admission.candidate.module_id != entry.module_id
        || admission.execution.module_id != entry.module_id
        || admission.execution.generation_id != admission.candidate.candidate_id
    {
        return Err(ModuleError::IdentityConflict);
    }
    // The policy revision is the fence's own value. A fence that carries none
    // has no policy revision to seal, and one is never derived from the restart
    // policy digest or from any other field.
    let Some(policy_revision) = admission.state_fence.policy_revision else {
        return Err(ModuleError::InvalidField {
            field: "seal.policy_revision",
            reason: "the admitting state fence carries no policy revision",
        });
    };
    // Only an admitted restart policy can be sealed, and it must be the exact
    // digest the accepted execution projection is already bound to. A withheld
    // disposition admits no policy to bind, so it is refused here rather than
    // sealed as an automatic restart authority.
    let Some(admitted_policy_digest) = entry.restart_policy_disposition.policy_digest() else {
        return Err(ModuleError::InvalidField {
            field: "seal.lifecycle_admission",
            reason: "the catalog withheld this generation's restart policy",
        });
    };
    if admitted_policy_digest != admission.execution.restart_policy_digest {
        return Err(ModuleError::IdentityConflict);
    }
    let operation_id = eliot_ors::OperationIdentity::new(change.operation_id.as_str())
        .map_err(sealed_projection_refusal)?;
    // The sealed projection records the admitting fence as a canonical snapshot
    // of that exact fence value, observed under the fence's own epoch sequence.
    // The snapshot is a capture of the recorded fence, not a re-statement of it.
    let state_fence = eliot_ors::StateFenceSnapshot::capture(
        &admission.state_fence,
        admission.state_fence.authority_epoch.sequence.get(),
    )
    .map_err(sealed_projection_refusal)?;
    let generation = sealed_generation_counter(&admission.execution.generation_id)?;
    let mut parts = eliot_ors::GovernorGenerationAdmissionSealParts {
        operation_id,
        idempotency_key: change.idempotency_key.clone(),
        module_id: admission.execution.module_id.as_str().to_owned(),
        generation,
        catalog_revision: admission.catalog_revision,
        policy_revision: policy_revision.value(),
        accepted_manifest_sha256: admission.execution.manifest_digest.clone(),
        state_fence,
        lifecycle_disposition: eliot_ors::LifecycleAdmissionDisposition::Admitted,
        // The canonical owner digest is computed over the other fields by the
        // sealed projection's own digest function, which recomputes it on every
        // validation; it is never a digest this owner invents.
        owner_canonical_sha256: String::new(),
    };
    parts.owner_canonical_sha256 =
        eliot_ors::GovernorGenerationAdmissionSeal::canonical_sha256(&parts)
            .map_err(sealed_projection_refusal)?;
    eliot_ors::GovernorGenerationAdmissionSeal::seal(parts).map_err(sealed_projection_refusal)
}

/// The generation counter the sealed projection records for this admission.
///
/// This catalog states the admitted generation as owner text ([`GenerationId`])
/// while the sealed projection states it as the numeric generation counter of the
/// Generation Registry. No field of the candidate, of the accepted execution
/// projection, of the accepting change or of the admitting State Fence relates
/// the two: the fence's own `resource_generation` is a different counter that no
/// join binds to this generation. The bridge is therefore refused here rather
/// than parsing one vocabulary into the other or substituting the fence's
/// counter, because either would manufacture a generation binding the Governor
/// never issued.
///
/// The refusal is raised before any sealed projection is constructed, so a
/// caller cannot reach the Kernel side with an unbound generation.
fn sealed_generation_counter(
    _admitted_generation: &GenerationId,
) -> Result<ResourceGeneration, ModuleError> {
    Err(ModuleError::InvalidField {
        field: "seal.generation",
        reason: "the admitted generation identity has no owner-declared numeric counter",
    })
}

/// Maps one sealed-projection refusal onto this owner's typed refusal.
///
/// The arms preserve the refusal each foreign variant states: a fence that does
/// not match stays a fence mismatch, a malformed sealed field stays an invalid
/// field, and a recorded field set whose canonical owner digest does not bind it
/// stays an identity conflict, which is the refusal this crate already records
/// when one of its own digests does not bind its recorded fields. Any other
/// foreign refusal is recorded as the contract failure it is, with the foreign
/// cause retained rather than dropped.
fn sealed_projection_refusal(error: eliot_ors::OrsError) -> ModuleError {
    match error {
        eliot_ors::OrsError::FenceMismatch => ModuleError::FenceMismatch,
        eliot_ors::OrsError::InvalidField { .. } => ModuleError::InvalidField {
            field: "seal",
            reason: "the sealed admission projection refused one of its own typed fields",
        },
        eliot_ors::OrsError::IntegrityProblem { .. } => ModuleError::IdentityConflict,
        other => ModuleError::Contract(other.to_string()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCatalogEntry {
    pub module_id: ModuleId,
    pub desired_state: DesiredModuleState,
    pub manifest: ModuleManifest,
    /// Explicit disposition of this entry's declared restart policy.
    ///
    /// It is recomputed from the manifest on every validation and compared with
    /// the stored value, so a recorded `Admitted`/`Withheld` cannot drift from
    /// the declaration it claims to describe. A manifest with no versioned
    /// policy is recorded as `Withheld`, which permits no automatic restart:
    /// the gap is named instead of defaulting to an unlimited budget.
    pub restart_policy_disposition: RestartPolicyDisposition,
    pub catalog_revision: u64,
    pub state_fence: StateFence,
    pub accepted_generation: Option<GenerationAdmission>,
    pub removal_reason: Option<String>,
}

impl ModuleCatalogEntry {
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.manifest.validate_for_module(&self.module_id)?;
        self.restart_policy_disposition
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        let declared = dispose_restart_policy(self.manifest.restart_policy.as_ref())
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        if declared != self.restart_policy_disposition {
            return Err(ModuleError::IdentityConflict);
        }
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        if self.catalog_revision == 0 {
            return Err(ModuleError::InvalidField {
                field: "catalog_revision",
                reason: "must be non-zero",
            });
        }
        if let Some(admission) = &self.accepted_generation {
            admission.validate()?;
            if admission.state_fence != self.state_fence
                || admission.catalog_revision > self.catalog_revision
            {
                return Err(ModuleError::FenceMismatch);
            }
        }
        if matches!(self.desired_state, DesiredModuleState::Removed)
            && self.removal_reason.as_deref().is_none_or(str::is_empty)
        {
            return Err(ModuleError::InvalidField {
                field: "removal_reason",
                reason: "removed modules require a reason",
            });
        }
        Ok(())
    }
}

/// Public mutation envelope; inline admission preserves the established wire
/// shape and constructor/API surface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum CatalogMutation {
    Upsert {
        manifest: ModuleManifest,
        desired_state: DesiredModuleState,
    },
    SetState {
        desired_state: DesiredModuleState,
        removal_reason: Option<String>,
    },
    AcceptGeneration {
        admission: GenerationAdmission,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCatalogChange {
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub module_id: ModuleId,
    pub expected_catalog_revision: u64,
    pub state_fence: StateFence,
    pub mutation: CatalogMutation,
    pub approval_refs: Vec<String>,
}

impl ModuleCatalogChange {
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        if self.expected_catalog_revision == 0 {
            return Err(ModuleError::InvalidField {
                field: "expected_catalog_revision",
                reason: "must be non-zero",
            });
        }
        text(&self.idempotency_key, "idempotency_key")?;
        unique(self.approval_refs.iter().cloned(), "approval_refs")?;
        for approval in &self.approval_refs {
            text(approval, "approval_ref")?;
        }
        match &self.mutation {
            CatalogMutation::Upsert { manifest, .. } => {
                manifest.validate_for_module(&self.module_id)?;
            }
            CatalogMutation::SetState { removal_reason, .. } => {
                if let Some(reason) = removal_reason {
                    text(reason, "removal_reason")?;
                }
            }
            CatalogMutation::AcceptGeneration { admission } => admission.validate()?,
        }
        Ok(())
    }

    pub fn canonical_request_digest(&self) -> Result<String, ModuleError> {
        self.validate()?;
        digest_value(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedCatalogTransition {
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub module_id: ModuleId,
    pub before_catalog_revision: u64,
    pub after_catalog_revision: u64,
    pub before_catalog_digest: String,
    pub after_catalog_digest: String,
    pub canonical_request_digest: String,
    pub state_fence: StateFence,
    pub admission_contract_digest: String,
    /// Dependents this transition invalidates, selected from the declared
    /// invalidation edges of the affected module.
    ///
    /// It is recorded rather than left implicit so the operational owner
    /// restarts exactly this set. It is empty for a change that replaces
    /// nothing and is derived by selection, never supplied by a caller: a
    /// caller-chosen list would be a copy of the caller's intent, not the
    /// graph.
    pub invalidated_dependents: Vec<ModuleId>,
    /// The declared trigger the selection was made under. It is absent exactly
    /// when no selection was made, so an empty set can never be read as "the
    /// graph was consulted and found nothing" unless the trigger says so.
    pub invalidation_trigger: Option<RestartInvalidationTrigger>,
    pub approval_refs: Vec<String>,
}

/// Compatibility spelling used by the public `ModuleCatalog` boundary.
pub type PreparedTransition = PreparedCatalogTransition;

impl PreparedCatalogTransition {
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.before_catalog_revision == 0
            || self.after_catalog_revision != self.before_catalog_revision + 1
        {
            return Err(ModuleError::RevisionConflict);
        }
        digest(&self.before_catalog_digest, "before_catalog_digest")?;
        digest(&self.after_catalog_digest, "after_catalog_digest")?;
        digest(&self.canonical_request_digest, "canonical_request_digest")?;
        digest(&self.admission_contract_digest, "admission_contract_digest")?;
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        text(&self.idempotency_key, "idempotency_key")?;
        unique(
            self.invalidated_dependents.iter().cloned(),
            "invalidated_dependents",
        )?;
        // A recorded dependent set without its trigger cannot be checked
        // against the graph, so the two are admitted or refused together.
        if self.invalidated_dependents.is_empty() != self.invalidation_trigger.is_none() {
            return Err(ModuleError::InvalidField {
                field: "invalidation_trigger",
                reason: "the selected dependent set and its trigger must agree",
            });
        }
        unique(self.approval_refs.iter().cloned(), "approval_refs")?;
        Ok(())
    }

    /// Checks the recorded dependent set against an expected set derived
    /// independently from the declared invalidation edges.
    ///
    /// `expected` must be the graph's own answer, not a copy of
    /// `self.invalidated_dependents`: this compares two separately derived sets
    /// so a selection that quietly dropped a declared dependent, or swept in an
    /// undeclared one, is caught. An absent trigger means nothing was selected
    /// and the set must be empty.
    pub fn verify_invalidation_dependents(&self, expected: &[ModuleId]) -> Result<(), ModuleError> {
        if self.invalidation_trigger.is_none() {
            return if self.invalidated_dependents.is_empty() {
                Ok(())
            } else {
                Err(ModuleError::InvalidField {
                    field: "invalidated_dependents",
                    reason: "a set was recorded without a declared trigger",
                })
            };
        }
        let recorded: BTreeSet<&ModuleId> = self.invalidated_dependents.iter().collect();
        let expected: BTreeSet<&ModuleId> = expected.iter().collect();
        if recorded != expected {
            return Err(ModuleError::InvalidField {
                field: "invalidated_dependents",
                reason: "the selected set does not match the declared invalidation edges",
            });
        }
        // The subject is always in its own affected set: a module that does not
        // join its own recovery was not selected at all.
        if !recorded.contains(&self.module_id) {
            return Err(ModuleError::InvalidField {
                field: "invalidated_dependents",
                reason: "the affected module is missing from its own dependent set",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCatalogSnapshotRequest {
    pub state_fence: StateFence,
    pub minimum_catalog_revision: Option<u64>,
}

impl ModuleCatalogSnapshotRequest {
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        if self.minimum_catalog_revision == Some(0) {
            return Err(ModuleError::InvalidField {
                field: "minimum_catalog_revision",
                reason: "must be non-zero when present",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCatalogSnapshot {
    pub catalog_revision: u64,
    pub state_fence: StateFence,
    pub entries: Vec<ModuleCatalogEntry>,
    pub catalog_digest: String,
}

impl ModuleCatalogSnapshot {
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.catalog_revision == 0 {
            return Err(ModuleError::InvalidField {
                field: "catalog_revision",
                reason: "must be non-zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        unique(
            self.entries.iter().map(|entry| entry.module_id.clone()),
            "entries.module_id",
        )?;
        for entry in &self.entries {
            entry.validate()?;
            if entry.catalog_revision > self.catalog_revision
                || entry.state_fence != self.state_fence
            {
                return Err(ModuleError::FenceMismatch);
            }
        }
        reject_required_dependency_cycle(&self.entries)?;
        digest(&self.catalog_digest, "catalog_digest")?;
        if self.computed_digest()? != self.catalog_digest {
            return Err(ModuleError::IdentityConflict);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Result<String, ModuleError> {
        digest_value(&(self.catalog_revision, &self.state_fence, &self.entries))
    }
}

/// Deterministic in-process catalog state machine used by the canonical writer.
/// Persistence and event/outbox delivery remain responsibilities of the store.
#[derive(Clone, Debug)]
pub struct ModuleCatalog {
    revision: u64,
    state_fence: StateFence,
    entries: BTreeMap<ModuleId, ModuleCatalogEntry>,
}

/// The entry one applied mutation produced, with the invalidation it recorded.
///
/// The trigger and the selection are carried as one value, not as two
/// separately derived facts: an entry arrives here either with both set, which
/// only a generation acceptance can do, or with neither. A mutation that only
/// changes desired state therefore cannot record a trigger, and a trigger
/// cannot be recorded without the set the same arm derived.
struct AppliedCatalogMutation {
    entry: ModuleCatalogEntry,
    invalidated_dependents: Vec<ModuleId>,
    invalidation_trigger: Option<RestartInvalidationTrigger>,
}

impl AppliedCatalogMutation {
    /// A mutation that invalidates nothing: no trigger, and the empty selection
    /// that an absent trigger is verified against.
    fn without_invalidation(entry: ModuleCatalogEntry) -> Self {
        Self {
            entry,
            invalidated_dependents: Vec::new(),
            invalidation_trigger: None,
        }
    }
}

impl ModuleCatalog {
    pub fn new(state_fence: StateFence) -> Result<Self, ModuleError> {
        state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        Ok(Self {
            revision: 1,
            state_fence,
            entries: BTreeMap::new(),
        })
    }

    pub fn from_snapshot(snapshot: ModuleCatalogSnapshot) -> Result<Self, ModuleError> {
        snapshot.validate()?;
        let mut entries = BTreeMap::new();
        for entry in snapshot.entries {
            if entries.insert(entry.module_id.clone(), entry).is_some() {
                return Err(ModuleError::Duplicate {
                    field: "snapshot.entries.module_id",
                });
            }
        }
        Ok(Self {
            revision: snapshot.catalog_revision,
            state_fence: snapshot.state_fence,
            entries,
        })
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    pub fn desired(&self, module_id: &ModuleId) -> Option<&ModuleCatalogEntry> {
        self.entries.get(module_id)
    }

    pub fn snapshot(&self) -> Result<ModuleCatalogSnapshot, ModuleError> {
        let snapshot = ModuleCatalogSnapshot {
            catalog_revision: self.revision,
            state_fence: self.state_fence.clone(),
            entries: self.entries.values().cloned().collect(),
            catalog_digest: String::new(),
        };
        let mut snapshot = snapshot;
        snapshot.catalog_digest = snapshot.computed_digest()?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn apply(
        &mut self,
        request: &ModuleCatalogChange,
    ) -> Result<PreparedCatalogTransition, ModuleError> {
        request.validate()?;
        if request.state_fence != self.state_fence {
            return Err(ModuleError::FenceMismatch);
        }
        if request.expected_catalog_revision != self.revision {
            return Err(ModuleError::RevisionConflict);
        }
        let before = self.snapshot()?;
        let previous = self.entries.get(&request.module_id).cloned();
        let applied = self.apply_mutation(&request.module_id, previous, &request.mutation)?;
        self.revision += 1;
        self.entries
            .insert(request.module_id.clone(), applied.entry);
        let after = self.snapshot()?;
        let prepared = PreparedCatalogTransition {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            module_id: request.module_id.clone(),
            before_catalog_revision: before.catalog_revision,
            after_catalog_revision: after.catalog_revision,
            before_catalog_digest: before.catalog_digest,
            after_catalog_digest: after.catalog_digest,
            canonical_request_digest: request.canonical_request_digest()?,
            state_fence: self.state_fence.clone(),
            admission_contract_digest: digest_value(&request.mutation)?,
            invalidated_dependents: applied.invalidated_dependents,
            invalidation_trigger: applied.invalidation_trigger,
            approval_refs: request.approval_refs.clone(),
        };
        prepared.validate()?;
        // Re-derive the affected set from the post-transition graph and check the
        // recorded selection against it. Two independent derivations of the same
        // declared edges must agree, so a selection that dropped a declared
        // dependent or swept in an undeclared one is refused before the
        // transition is returned to its owner. The check cannot pass by
        // comparing nothing: an empty selection is verified against an
        // independently derived empty set, not skipped. The set below is
        // derived, never read back off the transition, so the comparison is
        // between two derivations and not the selection with itself.
        let mut expected_dependents = Vec::new();
        if let Some(trigger) = prepared.invalidation_trigger {
            expected_dependents =
                self.select_invalidation_dependents(&request.module_id, trigger)?;
        }
        prepared.verify_invalidation_dependents(&expected_dependents)?;
        Ok(prepared)
    }

    /// Selects the dependents affected by an invalidation of `subject`, from
    /// declared invalidation edges only.
    ///
    /// This is the whole point of the graph: selection walks the edges each
    /// dependent *declared* (`ModuleDependency::invalidated_by`), never the
    /// startup order, never iteration order, and never "everything currently
    /// running". A module that declared no trigger on `subject` is not
    /// selected, so a later-started unrelated child stays running while an
    /// independent earlier sibling does too.
    ///
    /// The walk is transitive and bounded by the catalog's declared edge count,
    /// so a cyclic declaration cannot make it loop or silently truncate the
    /// closure. Optional and advisory edges are followed for the closure (a
    /// declared invalidation is a declared invalidation) but never create a
    /// liveness edge: their absence degrades a capability instead.
    ///
    /// `one_for_one` returns only the subject. `rest_for_one` adds the declared
    /// invalidated closure. `one_for_all` is rejected here: a group restart
    /// needs a finite named inseparable group plus accepted rationale, and
    /// refusing it before any effect is the only safe default for a request that
    /// arrived without them.
    pub fn select_invalidation_dependents(
        &self,
        subject: &ModuleId,
        trigger: RestartInvalidationTrigger,
    ) -> Result<Vec<ModuleId>, ModuleError> {
        let root = self.entries.get(subject).ok_or(ModuleError::NotFound)?;
        // The policy's own `subject_id` must name this module. A policy that
        // claims a different subject would supply another module's restart
        // strategy to this module's recovery, so the join is proved rather
        // than assumed.
        if let Some(policy) = root.manifest.restart_policy.as_ref()
            && policy.subject_id != subject.as_str()
        {
            return Err(ModuleError::IdentityConflict);
        }
        let strategy = root
            .manifest
            .restart_policy
            .as_ref()
            .map_or(RestartGroupStrategy::OneForOne, |policy| {
                policy.group_strategy
            });
        if strategy == RestartGroupStrategy::OneForAll {
            return Err(ModuleError::InvalidField {
                field: "group_strategy",
                reason: "one_for_all requires a named finite group and accepted rationale",
            });
        }
        if strategy == RestartGroupStrategy::OneForOne {
            return Ok(vec![subject.clone()]);
        }
        // `startup_order` is deliberately unread here. It orders startup, not
        // invalidation, and reading it is exactly the defect this replaces.
        let mut selected: BTreeSet<ModuleId> = BTreeSet::from([subject.clone()]);
        let mut frontier: Vec<ModuleId> = vec![subject.clone()];
        // The work bound is the total declared edge count of the catalog plus
        // the subject. Every selected module except the subject was reached
        // through at least one declared edge, so the closure cannot exceed it.
        // It is checked rather than assumed, so a malformed graph that selected
        // more than its own declarations justify is refused instead of being
        // returned as a complete affected set.
        let edge_budget = self
            .entries
            .values()
            .map(|entry| entry.manifest.dependencies.len())
            .sum::<usize>()
            + 1;
        let mut work = 0usize;
        while let Some(current) = frontier.pop() {
            for entry in self.entries.values() {
                // A dependent joins only because it declared this exact edge on
                // `current` carrying this exact trigger. No edge, no selection.
                let declares_invalidation = entry.manifest.dependencies.iter().any(|dependency| {
                    dependency.module_id == current && dependency.invalidated_by(trigger)
                });
                if !declares_invalidation || !selected.insert(entry.module_id.clone()) {
                    continue;
                }
                work = work.saturating_add(1);
                if work > edge_budget {
                    return Err(ModuleError::InvalidField {
                        field: "dependencies",
                        reason: "the selected set exceeds the declared edge bound",
                    });
                }
                frontier.push(entry.module_id.clone());
            }
        }
        Ok(selected.into_iter().collect())
    }

    /// Applies one catalog mutation to the entry it replaces, under the
    /// catalog's current revision and state fence.
    ///
    /// The order inside an arm is the order of the checks the catalog relies
    /// on, and each arm is refused before it replaces anything. Caller-supplied
    /// generation admissions remain refused until the owner receipt can be read
    /// back; desired-state `Upsert` and `SetState` change no accepted generation
    /// and invalidate nothing that is already running.
    fn apply_mutation(
        &self,
        module_id: &ModuleId,
        entry: Option<ModuleCatalogEntry>,
        mutation: &CatalogMutation,
    ) -> Result<AppliedCatalogMutation, ModuleError> {
        match mutation {
            CatalogMutation::Upsert {
                manifest,
                desired_state,
            } => {
                reject_self_dependency(manifest, module_id)?;
                let next = ModuleCatalogEntry {
                    module_id: module_id.clone(),
                    desired_state: *desired_state,
                    manifest: manifest.clone(),
                    restart_policy_disposition: dispose_restart_policy(
                        manifest.restart_policy.as_ref(),
                    )
                    .map_err(|error| ModuleError::Contract(error.to_string()))?,
                    catalog_revision: self.revision + 1,
                    state_fence: self.state_fence.clone(),
                    accepted_generation: entry
                        .as_ref()
                        .and_then(|existing| existing.accepted_generation.clone()),
                    removal_reason: None,
                };
                next.validate()?;
                Ok(AppliedCatalogMutation::without_invalidation(next))
            }
            CatalogMutation::SetState {
                desired_state,
                removal_reason,
            } => {
                let mut current = entry.ok_or(ModuleError::NotFound)?;
                current.desired_state = *desired_state;
                current.removal_reason.clone_from(removal_reason);
                current.catalog_revision = self.revision + 1;
                current.state_fence = self.state_fence.clone();
                current.validate()?;
                Ok(AppliedCatalogMutation::without_invalidation(current))
            }
            CatalogMutation::AcceptGeneration { .. } => {
                Err(ModuleError::AdmissionReceiptUnverified)
            }
        }
    }
}

/// A manifest that declares itself as its own dependency is refused, because
/// an invalidation edge from a module to itself would make every pull select
/// the subject as one of its own dependents.
fn reject_self_dependency(
    manifest: &ModuleManifest,
    subject: &ModuleId,
) -> Result<(), ModuleError> {
    if manifest
        .dependencies
        .iter()
        .any(|dependency| dependency.module_id == *subject)
    {
        return Err(ModuleError::InvalidField {
            field: "dependencies",
            reason: "a module cannot depend on itself",
        });
    }
    Ok(())
}

/// Refuses a cycle among the declared REQUIRED dependency edges.
///
/// I6.4 requires the required graph to be acyclic before a generation can
/// reach `READY`, and W2 requires exactly this for the restart policy's
/// required dependencies: only `RestartDependencyKind::Required` participates.
/// An optional or advisory edge is deliberately excluded, because its absence
/// degrades a capability rather than creating a liveness prerequisite
/// (I6.4), so including it here would refuse a declaration the architecture
/// admits.
///
/// The walk is over the catalog's own declared edges, so the refusal is a
/// property of what the manifests say rather than of any caller's list. The
/// offending path is reported, so the gap is named rather than summarized.
fn reject_required_dependency_cycle(entries: &[ModuleCatalogEntry]) -> Result<(), ModuleError> {
    let mut adjacency: BTreeMap<ModuleId, BTreeSet<ModuleId>> = BTreeMap::new();
    let mut nodes: BTreeSet<ModuleId> = BTreeSet::new();
    for entry in entries {
        nodes.insert(entry.module_id.clone());
        for dependency in &entry.manifest.dependencies {
            if dependency.kind != RestartDependencyKind::Required {
                continue;
            }
            // A required edge to a module outside this catalog is a leaf: that
            // provider's own required edges are declared by its own manifest,
            // not here, so this walk cannot traverse it and must not invent
            // the missing declaration.
            nodes.insert(dependency.module_id.clone());
            adjacency
                .entry(entry.module_id.clone())
                .or_default()
                .insert(dependency.module_id.clone());
        }
    }

    let mut color: BTreeMap<ModuleId, RequiredDependencyColor> = nodes
        .iter()
        .map(|node| (node.clone(), RequiredDependencyColor::White))
        .collect();
    let mut stack: Vec<ModuleId> = Vec::new();
    for node in &nodes {
        if color.get(node) == Some(&RequiredDependencyColor::White)
            && let Some(path) =
                visit_required_dependency_edges(node, &adjacency, &mut color, &mut stack)
        {
            return Err(ModuleError::RequiredDependencyCycle { path });
        }
    }
    Ok(())
}

/// Visit state of one node in the required-dependency acyclicity walk.
#[derive(Clone, Copy, Eq, PartialEq)]
enum RequiredDependencyColor {
    White,
    Gray,
    Black,
}

/// Visits one node's required edges, returning the cycle path when a node
/// already on the current stack is reached again.
fn visit_required_dependency_edges(
    node: &ModuleId,
    adjacency: &BTreeMap<ModuleId, BTreeSet<ModuleId>>,
    color: &mut BTreeMap<ModuleId, RequiredDependencyColor>,
    stack: &mut Vec<ModuleId>,
) -> Option<String> {
    color.insert(node.clone(), RequiredDependencyColor::Gray);
    stack.push(node.clone());
    if let Some(providers) = adjacency.get(node) {
        for provider in providers {
            match color.get(provider) {
                Some(RequiredDependencyColor::Gray) => {
                    let start = stack.iter().position(|id| id == provider).unwrap_or(0);
                    let mut path: Vec<String> =
                        stack[start..].iter().map(ToString::to_string).collect();
                    path.push(provider.to_string());
                    return Some(path.join(" -> "));
                }
                Some(RequiredDependencyColor::White) => {
                    if let Some(path) =
                        visit_required_dependency_edges(provider, adjacency, color, stack)
                    {
                        return Some(path);
                    }
                }
                Some(RequiredDependencyColor::Black) | None => {}
            }
        }
    }
    stack.pop();
    color.insert(node.clone(), RequiredDependencyColor::Black);
    None
}

#[allow(async_fn_in_trait)]
pub trait ModuleCatalogApi: Send + Sync {
    async fn desired(&self, module_id: ModuleId)
    -> Result<Option<ModuleCatalogEntry>, ModuleError>;

    async fn propose_change(
        &self,
        ctx: &RequestMetadata,
        request: ModuleCatalogChange,
    ) -> Result<PreparedTransition, ModuleError>;

    async fn snapshot(
        &self,
        request: ModuleCatalogSnapshotRequest,
    ) -> Result<ModuleCatalogSnapshot, ModuleError>;
}
