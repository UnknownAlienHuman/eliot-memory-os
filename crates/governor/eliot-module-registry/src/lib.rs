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
            manifest_digest: String::new(),
        };
        value.manifest_digest = value.identity_digest()?;
        value.validate()?;
        Ok(value)
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
            approved_scope_refs: &self.approved_scope_refs,
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
        unique(
            self.approved_scope_refs.iter().cloned(),
            "approved_scope_refs",
        )?;
        for scope in &self.approved_scope_refs {
            text(scope, "approved_scope_ref")?;
        }
        digest(&self.manifest_digest, "manifest_digest")?;
        if self.identity_digest()? != self.manifest_digest {
            return Err(ModuleError::IdentityConflict);
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
        self.state_fence
            .validate()
            .map_err(|error| ModuleError::Contract(error.to_string()))?;
        if self.catalog_revision == 0
            || self.catalog_revision != self.execution.accepted_catalog_revision
            || self.candidate.module_id != self.execution.module_id
            || self.candidate.candidate_id != self.execution.generation_id
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
        self.manifest.validate()?;
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
            CatalogMutation::AcceptGeneration { admission } => {
                let mut current = entry.ok_or(ModuleError::NotFound)?;
                if admission.candidate.module_id != request.module_id
                    || admission.state_fence != self.state_fence
                    || admission.catalog_revision != self.revision
                    || admission.candidate.artifact_digest != current.manifest.artifact_digest
                    || admission.candidate.config_digest != current.manifest.config_digest
                    || admission.candidate.protocol_digest != current.manifest.protocol_digest
                    || admission.execution.artifact_digest != current.manifest.artifact_digest
                    || admission.execution.config_digest != current.manifest.config_digest
                    || admission.execution.protocol_digest != current.manifest.protocol_digest
                    || admission.execution.command_ref != current.manifest.command_ref
                    || admission.execution.health_contract_ref
                        != current.manifest.health_contract_ref
                    || admission.execution.effect_ceiling != current.manifest.effect_ceiling
                    || admission.execution.restart_authorization
                        != current.manifest.restart_authorization
                {
                    return Err(ModuleError::IdentityConflict);
                }
                current.accepted_generation = Some(admission.clone());
                current.catalog_revision = self.revision + 1;
                current.state_fence = self.state_fence.clone();
                current.validate()?;
                entry = Some(current);
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
