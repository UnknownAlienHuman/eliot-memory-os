//! Governor-owned Module Catalog contracts.
//!
//! The catalog owns desired semantic configuration and admission intent. It
//! does not own PIDs, pipes, Job Objects, process health, route cutover, or
//! Kernel operational recovery state. A generation admission is an immutable
//! handoff to the Kernel Generation Registry; it is not activation authority.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{
    ContractVersion, OperationId, RequestMetadata, StateFence, canonical_json_bytes, sha256_hex,
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
    #[error("module catalog operation identity conflict")]
    IdentityConflict,
    #[error("module catalog serialization failed: {0}")]
    Serialization(String),
    #[error("module catalog contract failed: {0}")]
    Contract(String),
    #[error("module catalog generation admission is missing its execution policy")]
    MissingExecutionPolicy,
    #[error("module catalog admission receipt has no verified Catalog owner")]
    AdmissionReceiptUnverified,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleDependency {
    pub module_id: ModuleId,
    pub required_protocol_digest: String,
    pub startup_order: u32,
}

impl ModuleDependency {
    pub fn validate(&self) -> Result<(), ModuleError> {
        digest(
            &self.required_protocol_digest,
            "dependency.required_protocol_digest",
        )?;
        Ok(())
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
/// for the Kernel/ORS projection; it is never used to reconstruct them.
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

/// State-class behavior declared for the generation's I14.14 cutover.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleStateClassBehavior {
    RetainCompatible,
    CheckpointTransfer,
    RebuildFromSnapshot,
    ForwardRepairRequired,
}

/// The minimum source record needed to produce a complete I1.9 execution
/// manifest from a Governor-owned desired module.
///
/// REPORT assumption grounded in I1.9/I14.14: until a distinct versioned
/// policy-record owner exists, this policy is carried by the Module Manifest
/// that the Governor Catalog already owns. Admission requires every value and
/// copies it; this record assigns no defaults. ORS remains responsible for
/// the durable cutover decision and receipt.
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
                || !intent.effect_ceiling.admits(manifest.effect_ceiling)
            {
                return Err(ModuleError::IdentityConflict);
            }
        }
        if manifest.restart_authorization != RestartAuthorization::ReadRebuild
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

/// Source-derived technical projection prepared before a Catalog admission
/// receipt is available. It is not an accepted generation and cannot be
/// converted into ORS authority until the owner-issued receipt is read back.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedKernelExecutionProjection {
    pub artifact_digest: String,
    pub config_digest: String,
    pub protocol_digest: String,
    pub command_ref: String,
    pub dependency_order: Vec<ModuleDependency>,
    pub health_contract_ref: String,
    pub effect_ceiling: EffectCeiling,
    pub restart_authorization: RestartAuthorization,
    pub execution_policy: GenerationExecutionPolicy,
}

/// Governor Catalog join ready for the later receipt/readback owner.
///
/// This value intentionally has no admission receipt, accepted manifest digest,
/// or activation authority. It binds only the exact candidate to the current
/// Catalog row, policy revision, Catalog revision, and State Fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedGenerationExecution {
    pub candidate: GenerationCandidateReceipt,
    pub catalog_revision: u64,
    pub state_fence: StateFence,
    pub source_catalog_digest: String,
    pub source_manifest: ModuleManifest,
    pub source_manifest_digest: String,
    pub projection: PreparedKernelExecutionProjection,
}

impl PreparedGenerationExecution {
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.candidate.validate()?;
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        if self.catalog_revision == 0 {
            return Err(ModuleError::InvalidField {
                field: "prepared_execution.catalog_revision",
                reason: "must be greater than zero",
            });
        }
        digest(
            &self.source_catalog_digest,
            "prepared_execution.source_catalog_digest",
        )?;
        digest(
            &self.source_manifest_digest,
            "prepared_execution.source_manifest_digest",
        )?;
        self.source_manifest
            .validate_for_module(&self.candidate.module_id)?;
        if self.source_manifest.manifest_digest != self.source_manifest_digest {
            return Err(ModuleError::IdentityConflict);
        }
        let source_policy = self
            .source_manifest
            .execution_policy
            .as_ref()
            .ok_or(ModuleError::MissingExecutionPolicy)?;
        let mut source_dependencies = self.source_manifest.dependencies.clone();
        source_dependencies.sort_by_key(|dependency| dependency.startup_order);
        if self.projection.artifact_digest != self.source_manifest.artifact_digest
            || self.projection.config_digest != self.source_manifest.config_digest
            || self.projection.protocol_digest != self.source_manifest.protocol_digest
            || self.projection.command_ref != self.source_manifest.command_ref
            || self.projection.dependency_order != source_dependencies
            || self.projection.health_contract_ref != self.source_manifest.health_contract_ref
            || self.projection.effect_ceiling != self.source_manifest.effect_ceiling
            || self.projection.restart_authorization != self.source_manifest.restart_authorization
            || &self.projection.execution_policy != source_policy
        {
            return Err(ModuleError::IdentityConflict);
        }
        digest(
            &self.projection.artifact_digest,
            "prepared_execution.artifact_digest",
        )?;
        digest(
            &self.projection.config_digest,
            "prepared_execution.config_digest",
        )?;
        digest(
            &self.projection.protocol_digest,
            "prepared_execution.protocol_digest",
        )?;
        text(
            &self.projection.command_ref,
            "prepared_execution.command_ref",
        )?;
        text(
            &self.projection.health_contract_ref,
            "prepared_execution.health_contract_ref",
        )?;
        unique(
            self.projection
                .dependency_order
                .iter()
                .map(|dependency| dependency.module_id.clone()),
            "prepared_execution.dependency_order.module_id",
        )?;
        unique(
            self.projection
                .dependency_order
                .iter()
                .map(|dependency| dependency.startup_order),
            "prepared_execution.dependency_order.startup_order",
        )?;
        for dependency in &self.projection.dependency_order {
            dependency.validate()?;
        }
        self.projection.execution_policy.validate()?;
        if self.candidate.artifact_digest != self.projection.artifact_digest
            || self.candidate.config_digest != self.projection.config_digest
            || self.candidate.protocol_digest != self.projection.protocol_digest
            || self
                .projection
                .execution_policy
                .allowed_route_scopes
                .iter()
                .any(|scope| scope.module_id != self.candidate.module_id)
        {
            return Err(ModuleError::IdentityConflict);
        }
        Ok(())
    }
}

/// Exact owner inputs for preparing, but not yet accepting, one generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationPreparationRequest {
    pub candidate: GenerationCandidateReceipt,
    pub expected_catalog_revision: u64,
    pub state_fence: StateFence,
}

impl GenerationPreparationRequest {
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.candidate.validate()?;
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        if self.expected_catalog_revision == 0 {
            return Err(ModuleError::InvalidField {
                field: "expected_catalog_revision",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Desired execution description. It carries references and hashes, never
/// secret values, process handles, or a mutable route.
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
    pub approved_scope_refs: Vec<String>,
    /// Optional only for pre-admission Catalog rows. A generation cannot be
    /// accepted until the source owner supplies and validates this policy.
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
            approved_scope_refs,
            execution_policy: None,
            manifest_digest: String::new(),
        };
        value.manifest_digest = value.identity_digest()?;
        value.validate()?;
        Ok(value)
    }

    /// Attaches the source-owned execution policy without inventing defaults.
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
            approved_scope_refs: &'a [String],
        }

        let identity = Identity {
            artifact_digest: &self.artifact_digest,
            config_digest: &self.config_digest,
            protocol_digest: &self.protocol_digest,
            command_ref: &self.command_ref,
            health_contract_ref: &self.health_contract_ref,
            dependencies: &self.dependencies,
            capability_intents: &self.capability_intents,
            effect_ceiling: self.effect_ceiling,
            restart_authorization: self.restart_authorization,
            approved_scope_refs: &self.approved_scope_refs,
        };
        if let Some(execution_policy) = &self.execution_policy {
            digest_value(&(identity, execution_policy))
        } else {
            // Preserve the established digest of legacy desired rows that do
            // not yet carry an admission-ready execution policy.
            digest_value(&identity)
        }
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
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        unique(
            self.dependencies
                .iter()
                .map(|dependency| dependency.startup_order),
            "dependencies.startup_order",
        )?;
        unique(
            self.capability_intents
                .iter()
                .map(|intent| intent.capability_id.clone()),
            "capability_intents.capability_id",
        )?;
        for intent in &self.capability_intents {
            intent.validate()?;
        }
        unique(
            self.approved_scope_refs.iter().cloned(),
            "approved_scope_refs",
        )?;
        for scope in &self.approved_scope_refs {
            text(scope, "approved_scope_ref")?;
        }
        if let Some(execution_policy) = &self.execution_policy {
            execution_policy.validate()?;
        }
        digest(&self.manifest_digest, "manifest_digest")?;
        if self.identity_digest()? != self.manifest_digest {
            return Err(ModuleError::IdentityConflict);
        }
        Ok(())
    }

    fn validate_for_module(&self, module_id: &ModuleId) -> Result<(), ModuleError> {
        self.validate()?;
        if let Some(execution_policy) = &self.execution_policy {
            execution_policy.validate_for_module(module_id, self)?;
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
    pub build_provenance_digest: String,
    pub capability_profile_digest: String,
    pub source_fence_digest: String,
    pub candidate_digest: String,
}

impl GenerationCandidateReceipt {
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
        // I1.9 carries the accepted Catalog revision and receipt together.
        // This shape check preserves their join; it does not prove receipt
        // provenance. `ModuleCatalog::apply` therefore refuses this legacy
        // caller-supplied admission until an owner receipt can be read back.
        text(self.admission_receipt.as_str(), "admission_receipt")?;
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        if self.catalog_revision == 0
            || self.catalog_revision != self.execution.accepted_catalog_revision
            || self.candidate.module_id != self.execution.module_id
            || self.candidate.candidate_id != self.execution.generation_id
            || self.admission_receipt != self.execution.accepted_catalog_receipt
        {
            return Err(ModuleError::IdentityConflict);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCatalogEntry {
    pub module_id: ModuleId,
    pub desired_state: DesiredModuleState,
    pub manifest: ModuleManifest,
    pub catalog_revision: u64,
    pub state_fence: StateFence,
    pub accepted_generation: Option<GenerationAdmission>,
    pub removal_reason: Option<String>,
}

impl ModuleCatalogEntry {
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.manifest.validate_for_module(&self.module_id)?;
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
            CatalogMutation::Upsert { manifest, .. } => manifest.validate()?,
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
        unique(self.approval_refs.iter().cloned(), "approval_refs")?;
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

    /// Joins a candidate to the exact enabled Catalog row and produces a
    /// complete technical projection. This is preparation only: no Catalog
    /// row is marked accepted and no ORS manifest/receipt is issued.
    pub fn prepare_generation_execution(
        &self,
        request: &GenerationPreparationRequest,
    ) -> Result<PreparedGenerationExecution, ModuleError> {
        request.validate()?;
        if request.state_fence != self.state_fence {
            return Err(ModuleError::FenceMismatch);
        }
        if request.expected_catalog_revision != self.revision {
            return Err(ModuleError::RevisionConflict);
        }
        let source_catalog = self.snapshot()?;
        let entry = self
            .entries
            .get(&request.candidate.module_id)
            .ok_or(ModuleError::NotFound)?;
        if entry.desired_state != DesiredModuleState::Enabled {
            return Err(ModuleError::InvalidField {
                field: "desired_state",
                reason: "only enabled modules can prepare a generation",
            });
        }
        if request.candidate.artifact_digest != entry.manifest.artifact_digest
            || request.candidate.config_digest != entry.manifest.config_digest
            || request.candidate.protocol_digest != entry.manifest.protocol_digest
        {
            return Err(ModuleError::IdentityConflict);
        }
        let execution_policy = entry
            .manifest
            .execution_policy
            .clone()
            .ok_or(ModuleError::MissingExecutionPolicy)?;
        execution_policy.validate_for_module(&entry.module_id, &entry.manifest)?;
        let mut dependency_order = entry.manifest.dependencies.clone();
        dependency_order.sort_by_key(|dependency| dependency.startup_order);
        let prepared = PreparedGenerationExecution {
            candidate: request.candidate.clone(),
            catalog_revision: self.revision,
            state_fence: self.state_fence.clone(),
            source_catalog_digest: source_catalog.catalog_digest,
            source_manifest: entry.manifest.clone(),
            source_manifest_digest: entry.manifest.manifest_digest.clone(),
            projection: PreparedKernelExecutionProjection {
                artifact_digest: entry.manifest.artifact_digest.clone(),
                config_digest: entry.manifest.config_digest.clone(),
                protocol_digest: entry.manifest.protocol_digest.clone(),
                command_ref: entry.manifest.command_ref.clone(),
                dependency_order,
                health_contract_ref: entry.manifest.health_contract_ref.clone(),
                effect_ceiling: entry.manifest.effect_ceiling,
                restart_authorization: entry.manifest.restart_authorization,
                execution_policy,
            },
        };
        prepared.validate()?;
        Ok(prepared)
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
        let mut entry = self.entries.get(&request.module_id).cloned();
        match &request.mutation {
            CatalogMutation::Upsert {
                manifest,
                desired_state,
            } => {
                manifest.validate_for_module(&request.module_id)?;
                if manifest
                    .dependencies
                    .iter()
                    .any(|dependency| dependency.module_id == request.module_id)
                {
                    return Err(ModuleError::InvalidField {
                        field: "dependencies",
                        reason: "a module cannot depend on itself",
                    });
                }
                let next = ModuleCatalogEntry {
                    module_id: request.module_id.clone(),
                    desired_state: *desired_state,
                    manifest: manifest.clone(),
                    catalog_revision: self.revision + 1,
                    state_fence: self.state_fence.clone(),
                    accepted_generation: entry
                        .as_ref()
                        .and_then(|existing| existing.accepted_generation.clone()),
                    removal_reason: None,
                };
                next.validate()?;
                entry = Some(next);
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
                entry = Some(current);
            }
            CatalogMutation::AcceptGeneration { .. } => {
                return Err(ModuleError::AdmissionReceiptUnverified);
            }
        }
        let next_entry = entry.ok_or(ModuleError::NotFound)?;
        self.revision += 1;
        self.entries.insert(request.module_id.clone(), next_entry);
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
            approval_refs: request.approval_refs.clone(),
        };
        prepared.validate()?;
        Ok(prepared)
    }
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
